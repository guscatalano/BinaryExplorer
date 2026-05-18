using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class DependenciesInspector : IBinaryInspector
{
    public string Name => "Dependencies";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var stream = context.OpenStream();
                using var pe = new PEReader(stream);

                bool pe32Plus = pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus;
                int thunkSize = pe32Plus ? 8 : 4;
                ulong ordinalFlag = pe32Plus ? 0x8000000000000000UL : 0x80000000UL;

                ReadOnlySpan<byte> image = pe.GetEntireImage().GetContent().AsSpan();

                var staticImports = ReadStaticImports(pe, image, thunkSize, ordinalFlag);
                var delayImports = ReadDelayImports(pe, image, thunkSize, ordinalFlag);
                var exports = ReadExports(pe, image);

                int staticFnCount = staticImports.Sum(d => d.Functions.Count);
                int delayFnCount = delayImports.Sum(d => d.Functions.Count);

                findings.Add(new Finding(
                    "Static imports",
                    $"{staticImports.Count} DLLs, {staticFnCount} functions"));
                foreach (var d in staticImports.OrderBy(x => x.Dll, StringComparer.OrdinalIgnoreCase))
                {
                    findings.Add(new Finding(
                        d.Dll,
                        $"{d.Functions.Count} function(s)",
                        FormatFunctionList(d.Functions)));
                }

                if (delayImports.Count > 0)
                {
                    findings.Add(new Finding(
                        "Delay-loaded imports",
                        $"{delayImports.Count} DLLs, {delayFnCount} functions"));
                    foreach (var d in delayImports.OrderBy(x => x.Dll, StringComparer.OrdinalIgnoreCase))
                    {
                        findings.Add(new Finding(
                            $"[delay] {d.Dll}",
                            $"{d.Functions.Count} function(s)",
                            FormatFunctionList(d.Functions)));
                    }
                }
                else
                {
                    findings.Add(new Finding("Delay-loaded imports", "0"));
                }

                if (exports is not null)
                {
                    findings.Add(new Finding(
                        "Exports",
                        $"{exports.Names.Count} named, OrdinalBase={exports.OrdinalBase}, NumberOfFunctions={exports.NumberOfFunctions}",
                        FormatFunctionList(exports.Names)));
                    if (exports.Forwarders.Count > 0)
                    {
                        findings.Add(new Finding(
                            "Forwarders",
                            $"{exports.Forwarders.Count}",
                            string.Join("\n", exports.Forwarders.Select(f => $"{f.Name} -> {f.Target}"))));
                    }
                }
                else
                {
                    findings.Add(new Finding("Exports", "None (no export directory)"));
                }

                if (pe.HasMetadata)
                {
                    var md = pe.GetMetadataReader();
                    var refs = new List<(string Name, Version Version, string? Token)>();
                    foreach (var h in md.AssemblyReferences)
                    {
                        var a = md.GetAssemblyReference(h);
                        string? token = null;
                        if (!a.PublicKeyOrToken.IsNil)
                        {
                            var bytes = md.GetBlobBytes(a.PublicKeyOrToken);
                            token = Convert.ToHexString(bytes).ToLowerInvariant();
                        }
                        refs.Add((md.GetString(a.Name), a.Version, token));
                    }
                    findings.Add(new Finding(
                        "Managed assembly references",
                        refs.Count.ToString()));
                    foreach (var r in refs.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        findings.Add(new Finding(
                            r.Name,
                            r.Version.ToString(),
                            r.Token is null ? null : $"PublicKey/Token: {r.Token}"));
                    }
                }

                string headline = (staticImports.Count, delayImports.Count, exports?.Names.Count ?? 0) switch
                {
                    (0, 0, 0) => "No imports or exports",
                    var (s, d, e) => $"{s} static DLL(s)" + (d > 0 ? $", {d} delay-loaded" : "") + (e > 0 ? $", {e} exports" : ""),
                };

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
                    Headline = "Dependency inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static string FormatFunctionList(IReadOnlyCollection<string> functions)
    {
        if (functions.Count == 0) return "(none)";
        const int max = 50;
        if (functions.Count <= max) return string.Join("\n", functions);
        return string.Join("\n", functions.Take(max)) + $"\n... and {functions.Count - max} more";
    }

    private sealed class DllImports
    {
        public string Dll = "";
        public List<string> Functions = new();
    }

    private static List<DllImports> ReadStaticImports(PEReader pe, ReadOnlySpan<byte> image, int thunkSize, ulong ordinalFlag)
    {
        var result = new List<DllImports>();
        var dir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return result;

        int rva = dir.Value.RelativeVirtualAddress;
        if (!LanguageInspector.TryRvaToOffset(pe, rva, out int offset)) return result;

        while (offset + 20 <= image.Length)
        {
            uint origFirstThunk = BitConverter.ToUInt32(image.Slice(offset, 4));
            uint nameRva = BitConverter.ToUInt32(image.Slice(offset + 12, 4));
            uint firstThunk = BitConverter.ToUInt32(image.Slice(offset + 16, 4));
            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            var dll = new DllImports();
            if (nameRva != 0 && LanguageInspector.TryRvaToOffset(pe, (int)nameRva, out int nameOff))
                dll.Dll = ReadAsciiZ(image, nameOff);

            uint thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            if (thunkRva != 0 && LanguageInspector.TryRvaToOffset(pe, (int)thunkRva, out int thunkOff))
                ReadThunkArray(pe, image, thunkOff, thunkSize, ordinalFlag, dll.Functions);

            result.Add(dll);
            offset += 20;
        }
        return result;
    }

    private static List<DllImports> ReadDelayImports(PEReader pe, ReadOnlySpan<byte> image, int thunkSize, ulong ordinalFlag)
    {
        var result = new List<DllImports>();
        var dir = pe.PEHeaders.PEHeader?.DelayImportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return result;

        int rva = dir.Value.RelativeVirtualAddress;
        if (!LanguageInspector.TryRvaToOffset(pe, rva, out int offset)) return result;

        // IMAGE_DELAY_IMPORT_DESCRIPTOR (32 bytes):
        //   uint32 Attributes
        //   uint32 DllNameRVA
        //   uint32 HModuleRVA
        //   uint32 ImportAddressTableRVA
        //   uint32 ImportNameTableRVA
        //   uint32 BoundImportAddressTableRVA
        //   uint32 UnloadInformationTableRVA
        //   uint32 TimeDateStamp
        while (offset + 32 <= image.Length)
        {
            uint dllNameRva = BitConverter.ToUInt32(image.Slice(offset + 4, 4));
            uint intRva = BitConverter.ToUInt32(image.Slice(offset + 16, 4));
            if (dllNameRva == 0 && intRva == 0) break;

            var dll = new DllImports();
            if (dllNameRva != 0 && LanguageInspector.TryRvaToOffset(pe, (int)dllNameRva, out int nameOff))
                dll.Dll = ReadAsciiZ(image, nameOff);
            if (intRva != 0 && LanguageInspector.TryRvaToOffset(pe, (int)intRva, out int thunkOff))
                ReadThunkArray(pe, image, thunkOff, thunkSize, ordinalFlag, dll.Functions);

            result.Add(dll);
            offset += 32;
        }
        return result;
    }

    private static void ReadThunkArray(
        PEReader pe,
        ReadOnlySpan<byte> image,
        int offset,
        int thunkSize,
        ulong ordinalFlag,
        List<string> functions)
    {
        while (offset + thunkSize <= image.Length)
        {
            ulong thunk = thunkSize == 8
                ? BitConverter.ToUInt64(image.Slice(offset, 8))
                : BitConverter.ToUInt32(image.Slice(offset, 4));
            if (thunk == 0) break;
            offset += thunkSize;

            if ((thunk & ordinalFlag) != 0)
            {
                ushort ord = (ushort)(thunk & 0xFFFF);
                functions.Add($"#{ord}");
            }
            else
            {
                int hintNameRva = (int)(thunk & 0x7FFFFFFF);
                if (LanguageInspector.TryRvaToOffset(pe, hintNameRva, out int hnOff) && hnOff + 2 < image.Length)
                {
                    // IMAGE_IMPORT_BY_NAME: ushort hint, then null-terminated ASCII name
                    string name = ReadAsciiZ(image, hnOff + 2);
                    if (name.Length > 0) functions.Add(name);
                }
            }
        }
    }

    private sealed class ExportInfo
    {
        public uint OrdinalBase;
        public uint NumberOfFunctions;
        public List<string> Names = new();
        public List<(string Name, string Target)> Forwarders = new();
    }

    private static ExportInfo? ReadExports(PEReader pe, ReadOnlySpan<byte> image)
    {
        var dir = pe.PEHeaders.PEHeader?.ExportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return null;
        int rva = dir.Value.RelativeVirtualAddress;
        int size = dir.Value.Size;
        if (!LanguageInspector.TryRvaToOffset(pe, rva, out int offset)) return null;

        // IMAGE_EXPORT_DIRECTORY (40 bytes)
        uint ordinalBase = BitConverter.ToUInt32(image.Slice(offset + 16, 4));
        uint numberOfFunctions = BitConverter.ToUInt32(image.Slice(offset + 20, 4));
        uint numberOfNames = BitConverter.ToUInt32(image.Slice(offset + 24, 4));
        uint addressOfFunctions = BitConverter.ToUInt32(image.Slice(offset + 28, 4));
        uint addressOfNames = BitConverter.ToUInt32(image.Slice(offset + 32, 4));
        uint addressOfNameOrdinals = BitConverter.ToUInt32(image.Slice(offset + 36, 4));

        var info = new ExportInfo { OrdinalBase = ordinalBase, NumberOfFunctions = numberOfFunctions };

        if (numberOfNames > 0
            && LanguageInspector.TryRvaToOffset(pe, (int)addressOfNames, out int nameTableOff)
            && LanguageInspector.TryRvaToOffset(pe, (int)addressOfNameOrdinals, out int ordTableOff)
            && LanguageInspector.TryRvaToOffset(pe, (int)addressOfFunctions, out int fnTableOff))
        {
            for (int i = 0; i < numberOfNames; i++)
            {
                int nameRvaOff = nameTableOff + i * 4;
                if (nameRvaOff + 4 > image.Length) break;
                uint nameRva = BitConverter.ToUInt32(image.Slice(nameRvaOff, 4));
                if (!LanguageInspector.TryRvaToOffset(pe, (int)nameRva, out int nOff)) continue;
                string fnName = ReadAsciiZ(image, nOff);
                info.Names.Add(fnName);

                // Check if the matching function RVA points back into the export directory → forwarder
                int ordOff = ordTableOff + i * 2;
                if (ordOff + 2 > image.Length) continue;
                ushort ord = BitConverter.ToUInt16(image.Slice(ordOff, 2));
                int fnRvaOff = fnTableOff + ord * 4;
                if (fnRvaOff + 4 > image.Length) continue;
                uint fnRva = BitConverter.ToUInt32(image.Slice(fnRvaOff, 4));
                if (fnRva >= rva && fnRva < rva + size)
                {
                    if (LanguageInspector.TryRvaToOffset(pe, (int)fnRva, out int fOff))
                    {
                        string target = ReadAsciiZ(image, fOff);
                        info.Forwarders.Add((fnName, target));
                    }
                }
            }
        }
        return info;
    }

    private static string ReadAsciiZ(ReadOnlySpan<byte> image, int offset)
    {
        int end = offset;
        while (end < image.Length && image[end] != 0) end++;
        if (end == offset) return "";
        return Encoding.ASCII.GetString(image.Slice(offset, end - offset));
    }
}
