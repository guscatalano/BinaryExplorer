using System.Reflection.PortableExecutable;
using System.Text;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class DebugInfoInspector : IBinaryInspector
{
    public string Name => "Debug";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var ms = new MemoryStream(context.Bytes, writable: false);
                using var pe = new PEReader(ms);
                var dir = pe.PEHeaders.PEHeader?.DebugTableDirectory;
                if (dir is null || dir.Value.Size == 0)
                {
                    findings.Add(new Finding("Debug directory", "Not present"));
                    return new InspectionResult { InspectorName = Name, Headline = "No debug info", Findings = findings };
                }

                if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int debugOff))
                {
                    findings.Add(new Finding("Debug directory", "RVA could not be resolved"));
                    return new InspectionResult { InspectorName = Name, Headline = "Debug RVA unresolved", Findings = findings };
                }

                int entrySize = 28;
                int count = dir.Value.Size / entrySize;
                findings.Add(new Finding("Debug directory entries", count.ToString()));

                string headline = "Debug info present";

                for (int i = 0; i < count; i++)
                {
                    int e = debugOff + i * entrySize;
                    if (e + entrySize > context.Bytes.Length) break;
                    uint timestamp = BitConverter.ToUInt32(context.Bytes, e + 4);
                    uint type = BitConverter.ToUInt32(context.Bytes, e + 12);
                    uint sizeOfData = BitConverter.ToUInt32(context.Bytes, e + 16);
                    uint addrRva = BitConverter.ToUInt32(context.Bytes, e + 20);
                    uint pointerToRawData = BitConverter.ToUInt32(context.Bytes, e + 24);

                    string typeName = type switch
                    {
                        0 => "Unknown",
                        1 => "COFF",
                        2 => "CodeView (PDB)",
                        3 => "FPO",
                        4 => "Misc",
                        5 => "Exception",
                        6 => "Fixup",
                        9 => "Borland",
                        12 => "VC Feature",
                        13 => "POGO",
                        14 => "ILTCG",
                        15 => "MPX",
                        16 => "Repro",
                        20 => "Ex DLL Characteristics",
                        _ => $"type {type}",
                    };

                    var ts = DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime;
                    findings.Add(new Finding(
                        $"Entry [{i}] {typeName}",
                        $"size={sizeOfData} ts={ts:u}",
                        $"AddressOfRawData=0x{addrRva:X}, PointerToRawData=0x{pointerToRawData:X}"));

                    if (type == 2 && pointerToRawData > 0 && pointerToRawData + sizeOfData <= context.Bytes.Length)
                    {
                        // CV_INFO_PDB70: 'RSDS' + GUID(16) + age(4) + null-terminated path
                        int p = (int)pointerToRawData;
                        if (sizeOfData >= 24
                            && context.Bytes[p] == 'R' && context.Bytes[p + 1] == 'S' && context.Bytes[p + 2] == 'D' && context.Bytes[p + 3] == 'S')
                        {
                            var guidBytes = new byte[16];
                            Array.Copy(context.Bytes, p + 4, guidBytes, 0, 16);
                            var guid = new Guid(guidBytes);
                            uint age = BitConverter.ToUInt32(context.Bytes, p + 20);
                            int pathStart = p + 24;
                            int pathEnd = pathStart;
                            while (pathEnd < p + sizeOfData && context.Bytes[pathEnd] != 0) pathEnd++;
                            string path = Encoding.UTF8.GetString(context.Bytes, pathStart, pathEnd - pathStart);
                            findings.Add(new Finding("PDB GUID", guid.ToString("N").ToUpperInvariant()));
                            findings.Add(new Finding("PDB Age", age.ToString()));
                            findings.Add(new Finding("PDB Path", path));
                            // The symbol-store hash is GUID concat with hex age (no dashes, all upper).
                            string symHash = guid.ToString("N").ToUpperInvariant() + age.ToString("X").ToUpperInvariant();
                            findings.Add(new Finding("PDB symstore hash", symHash));
                            headline = $"PDB: {System.IO.Path.GetFileName(path)}";
                        }
                    }

                    if (type == 16 && sizeOfData == 0)
                    {
                        findings.Add(new Finding(
                            "Reproducible build",
                            "Yes",
                            "IMAGE_DEBUG_TYPE_REPRO indicates the compiler stripped timestamps for reproducibility.",
                            Severity.Info));
                    }
                }

                return new InspectionResult { InspectorName = Name, Headline = headline, Findings = findings };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Debug info inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }
}
