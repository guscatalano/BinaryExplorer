using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class LanguageInspector : IBinaryInspector
{
    public string Name => "Language";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var stream = context.OpenStream();
                using var pe = new PEReader(stream);

                var coff = pe.PEHeaders.CoffHeader;
                var opt = pe.PEHeaders.PEHeader;

                string arch = coff.Machine switch
                {
                    Machine.Amd64 => "x64",
                    Machine.I386 => "x86",
                    Machine.Arm64 => "ARM64",
                    Machine.Arm or Machine.ArmThumb2 => "ARM",
                    Machine.IA64 => "IA64",
                    _ => coff.Machine.ToString(),
                };
                findings.Add(new Finding("Architecture", arch));

                string subsystem = opt?.Subsystem.ToString() ?? "Unknown";
                findings.Add(new Finding("Subsystem", subsystem));

                bool isManaged = pe.HasMetadata;
                string headline;
                if (isManaged)
                {
                    var md = pe.GetMetadataReader();
                    string flavor = DetectClrFlavor(md);
                    string? tfm = TryGetTargetFramework(md);
                    headline = $"Managed .NET ({flavor})";
                    findings.Add(new Finding("Runtime", "Managed (.NET)"));
                    findings.Add(new Finding(".NET Flavor", flavor));
                    if (tfm is not null) findings.Add(new Finding("TargetFramework", tfm));

                    var corFlags = pe.PEHeaders.CorHeader?.Flags ?? 0;
                    findings.Add(new Finding("CorFlags", corFlags.ToString()));

                    if (md.IsAssembly)
                    {
                        var asm = md.GetAssemblyDefinition();
                        findings.Add(new Finding("Assembly", md.GetString(asm.Name)));
                        findings.Add(new Finding("AssemblyVersion", asm.Version.ToString()));
                    }
                }
                else
                {
                    headline = "Native (C/C++ or other unmanaged)";
                    findings.Add(new Finding("Runtime", "Native"));
                    var lang = GuessNativeLanguage(pe);
                    findings.Add(new Finding("Likely Language", lang));
                }

                if (opt is not null)
                {
                    findings.Add(new Finding(
                        "LinkerVersion",
                        $"{opt.MajorLinkerVersion}.{opt.MinorLinkerVersion}"));
                }
                var ts = DateTimeOffset.FromUnixTimeSeconds(coff.TimeDateStamp).UtcDateTime;
                findings.Add(new Finding("CompileTimestamp", ts.ToString("u")));

                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = headline,
                    Findings = findings,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static string DetectClrFlavor(MetadataReader md)
    {
        foreach (var handle in md.AssemblyReferences)
        {
            var asmRef = md.GetAssemblyReference(handle);
            var name = md.GetString(asmRef.Name);
            if (name.Equals("System.Runtime", StringComparison.OrdinalIgnoreCase))
                return $".NET Core/.NET 5+ (refs System.Runtime {asmRef.Version})";
            if (name.Equals("mscorlib", StringComparison.OrdinalIgnoreCase))
            {
                if (asmRef.Version.Major >= 4)
                    return $".NET Framework 4.x (mscorlib {asmRef.Version})";
                return $".NET Framework {asmRef.Version.Major}.x (mscorlib {asmRef.Version})";
            }
            if (name.Equals("netstandard", StringComparison.OrdinalIgnoreCase))
                return $".NET Standard (netstandard {asmRef.Version})";
        }
        return "Unknown CLR";
    }

    private static string? TryGetTargetFramework(MetadataReader md)
    {
        foreach (var handle in md.CustomAttributes)
        {
            var attr = md.GetCustomAttribute(handle);
            string? ctorName = ResolveAttributeTypeName(md, attr);
            if (ctorName == "System.Runtime.Versioning.TargetFrameworkAttribute")
            {
                var blob = md.GetBlobReader(attr.Value);
                if (blob.ReadUInt16() != 0x0001) continue;
                var s = blob.ReadSerializedString();
                return s;
            }
        }
        return null;
    }

    private static string? ResolveAttributeTypeName(MetadataReader md, CustomAttribute attr)
    {
        switch (attr.Constructor.Kind)
        {
            case HandleKind.MemberReference:
                {
                    var mref = md.GetMemberReference((MemberReferenceHandle)attr.Constructor);
                    if (mref.Parent.Kind == HandleKind.TypeReference)
                    {
                        var tref = md.GetTypeReference((TypeReferenceHandle)mref.Parent);
                        return $"{md.GetString(tref.Namespace)}.{md.GetString(tref.Name)}";
                    }
                    return null;
                }
            case HandleKind.MethodDefinition:
                {
                    var mdef = md.GetMethodDefinition((MethodDefinitionHandle)attr.Constructor);
                    var tdef = md.GetTypeDefinition(mdef.GetDeclaringType());
                    return $"{md.GetString(tdef.Namespace)}.{md.GetString(tdef.Name)}";
                }
            default:
                return null;
        }
    }

    private static string GuessNativeLanguage(PEReader pe)
    {
        // Heuristic: scan import DLL names for hints.
        try
        {
            var importDir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
            if (importDir is null || importDir.Value.Size == 0) return "C/C++ (no imports table)";

            var imports = ReadImportedDllNames(pe);
            if (imports.Any(i => i.StartsWith("msvcr", StringComparison.OrdinalIgnoreCase)
                              || i.StartsWith("vcruntime", StringComparison.OrdinalIgnoreCase)
                              || i.StartsWith("msvcp", StringComparison.OrdinalIgnoreCase)
                              || i.StartsWith("ucrtbase", StringComparison.OrdinalIgnoreCase)))
                return "C/C++ (MSVC runtime)";
            if (imports.Any(i => i.Equals("msvbvm60.dll", StringComparison.OrdinalIgnoreCase)))
                return "Visual Basic 6";
            if (imports.Any(i => i.StartsWith("python", StringComparison.OrdinalIgnoreCase)))
                return "Python (embedded)";
            if (imports.Any(i => i.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase)))
                return "C/C++ (Windows native)";
            return "Unknown native";
        }
        catch
        {
            return "Unknown native";
        }
    }

    internal static List<string> ReadImportedDllNames(PEReader pe)
    {
        var list = new List<string>();
        var importDir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
        if (importDir is null || importDir.Value.Size == 0) return list;

        int rva = importDir.Value.RelativeVirtualAddress;
        if (!TryRvaToOffset(pe, rva, out int offset)) return list;

        var image = pe.GetEntireImage().GetContent();
        // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes; terminated by all-zero descriptor.
        while (offset + 20 <= image.Length)
        {
            uint origFirstThunk = BitConverter.ToUInt32(image.AsSpan(offset, 4));
            uint nameRva = BitConverter.ToUInt32(image.AsSpan(offset + 12, 4));
            uint firstThunk = BitConverter.ToUInt32(image.AsSpan(offset + 16, 4));
            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            if (nameRva != 0 && TryRvaToOffset(pe, (int)nameRva, out int nameOffset))
            {
                int end = nameOffset;
                while (end < image.Length && image[end] != 0) end++;
                if (end > nameOffset)
                {
                    var name = System.Text.Encoding.ASCII.GetString(image.AsSpan(nameOffset, end - nameOffset));
                    list.Add(name);
                }
            }
            offset += 20;
        }
        return list;
    }

    internal static bool TryRvaToOffset(PEReader pe, int rva, out int offset)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize)
            {
                offset = s.PointerToRawData + (rva - s.VirtualAddress);
                return true;
            }
        }
        offset = 0;
        return false;
    }
}
