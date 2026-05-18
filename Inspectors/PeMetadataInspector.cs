using System.Reflection.PortableExecutable;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class PeMetadataInspector : IBinaryInspector
{
    public string Name => "PE";

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

                findings.Add(new Finding("Machine", coff.Machine.ToString()));
                findings.Add(new Finding("Characteristics", coff.Characteristics.ToString()));
                findings.Add(new Finding("NumberOfSections", coff.NumberOfSections.ToString()));
                findings.Add(new Finding("PointerToSymbolTable", "0x" + coff.PointerToSymbolTable.ToString("X")));
                findings.Add(new Finding("SizeOfOptionalHeader", coff.SizeOfOptionalHeader.ToString()));

                if (opt is not null)
                {
                    findings.Add(new Finding("Magic", opt.Magic.ToString()));
                    findings.Add(new Finding("Subsystem", opt.Subsystem.ToString()));
                    findings.Add(new Finding("DllCharacteristics", opt.DllCharacteristics.ToString()));
                    findings.Add(new Finding("SizeOfImage", "0x" + opt.SizeOfImage.ToString("X")));
                    findings.Add(new Finding("SizeOfCode", "0x" + opt.SizeOfCode.ToString("X")));
                    findings.Add(new Finding("EntryPoint", "0x" + opt.AddressOfEntryPoint.ToString("X")));
                    findings.Add(new Finding("ImageBase", "0x" + opt.ImageBase.ToString("X")));
                    findings.Add(new Finding(
                        "OS Version",
                        $"{opt.MajorOperatingSystemVersion}.{opt.MinorOperatingSystemVersion}"));
                    findings.Add(new Finding(
                        "Subsystem Version",
                        $"{opt.MajorSubsystemVersion}.{opt.MinorSubsystemVersion}"));
                }

                int sIdx = 0;
                foreach (var s in pe.PEHeaders.SectionHeaders)
                {
                    findings.Add(new Finding(
                        $"Section[{sIdx++}] {s.Name}",
                        $"VA=0x{s.VirtualAddress:X8} VSize=0x{s.VirtualSize:X} RawSize=0x{s.SizeOfRawData:X}",
                        s.SectionCharacteristics.ToString()));
                }

                var imports = LanguageInspector.ReadImportedDllNames(pe);
                findings.Add(new Finding("ImportedDlls", imports.Count.ToString(), string.Join(", ", imports)));

                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = $"{coff.Machine}, {coff.NumberOfSections} sections, {imports.Count} import DLLs",
                    Findings = findings,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "PE inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }
}
