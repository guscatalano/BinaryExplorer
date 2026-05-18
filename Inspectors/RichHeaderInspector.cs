using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class RichHeaderInspector : IBinaryInspector
{
    public string Name => "RichHeader";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                var bytes = context.Bytes;
                if (bytes.Length < 0x80)
                {
                    findings.Add(new Finding("Rich header", "File too small"));
                    return Result();
                }
                int peOffset = BitConverter.ToInt32(bytes, 0x3C);
                if (peOffset <= 0 || peOffset > bytes.Length)
                {
                    findings.Add(new Finding("Rich header", "No valid PE header offset"));
                    return Result();
                }

                // The Rich header lives between the DOS stub and the PE header (e_lfanew).
                // Look for the ASCII 'Rich' tag.
                var slice = bytes.AsSpan(0, Math.Min(peOffset, bytes.Length));
                int richIdx = slice.LastIndexOf(new byte[] { (byte)'R', (byte)'i', (byte)'c', (byte)'h' });
                if (richIdx < 0)
                {
                    findings.Add(new Finding("Rich header", "Not present (no 'Rich' marker)",
                        "Common for non-MSVC binaries (mingw, clang via lld, Go, Rust without MSVC linker)."));
                    return Result();
                }
                if (richIdx + 8 > slice.Length)
                {
                    findings.Add(new Finding("Rich header", "Truncated"));
                    return Result();
                }

                uint xorKey = BitConverter.ToUInt32(bytes, richIdx + 4);
                // Walk backward in 4-byte DWORDs XORing by the key, looking for the 'DanS' tag.
                int dansIdx = -1;
                for (int i = richIdx - 4; i >= 0; i -= 4)
                {
                    uint dword = BitConverter.ToUInt32(bytes, i);
                    if ((dword ^ xorKey) == 0x536E6144u) // 'DanS' little-endian
                    {
                        dansIdx = i;
                        break;
                    }
                }
                if (dansIdx < 0)
                {
                    findings.Add(new Finding("Rich header", "'DanS' tag not found", $"Rich tag at 0x{richIdx:X}, XOR key 0x{xorKey:X8}", Severity.Warning));
                    return Result();
                }

                findings.Add(new Finding("XOR key", $"0x{xorKey:X8}"));
                findings.Add(new Finding("Range", $"DanS at 0x{dansIdx:X}, Rich at 0x{richIdx:X} ({richIdx - dansIdx} bytes)"));

                // After 'DanS' there are 3 padding DWORDs (also XOR'd, all 0 when decoded), then comp ID records.
                // Each record: 2 DWORDs. First DWORD = compid (upper 16 bits = build, lower 16 bits = product id).
                // Second DWORD = count.
                int recStart = dansIdx + 16;
                var records = new List<(int Build, int ProductId, int Count)>();
                for (int i = recStart; i + 8 <= richIdx; i += 8)
                {
                    uint a = BitConverter.ToUInt32(bytes, i) ^ xorKey;
                    uint b = BitConverter.ToUInt32(bytes, i + 4) ^ xorKey;
                    int productId = (int)(a & 0xFFFF);
                    int build = (int)((a >> 16) & 0xFFFF);
                    int count = (int)b;
                    records.Add((build, productId, count));
                }

                findings.Add(new Finding("Comp ID records", records.Count.ToString(),
                    string.Join("\n", records.Select(r =>
                        $"  prodId={r.ProductId,5} ({ProductIdName(r.ProductId)})  build={r.Build,5}  count={r.Count}"))));

                string headline = $"Rich header present — {records.Count} comp ID record(s)";
                return new InspectionResult { InspectorName = Name, Headline = headline, Findings = findings };

                InspectionResult Result() => new InspectionResult
                {
                    InspectorName = Name,
                    Headline = findings.FirstOrDefault()?.Value ?? "Rich header status",
                    Findings = findings,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Rich header inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    // Selected product IDs — there are hundreds; these are the most common.
    private static string ProductIdName(int id) => id switch
    {
        0x00 => "Unknown",
        0x01 => "Import (linker)",
        0x02 => "Linker MASM 6.13",
        0x06 => "Resource compiler",
        0x0a => "C compiler (VC++ 6)",
        0x0b => "C++ compiler (VC++ 6)",
        0x15 => "C compiler (VS 2002)",
        0x16 => "C++ compiler (VS 2002)",
        0x19 => "C compiler (VS 2003)",
        0x1a => "C++ compiler (VS 2003)",
        0x1c => "Linker (VS 2003)",
        0x5d => "C compiler (VS 2005)",
        0x5e => "C++ compiler (VS 2005)",
        0x83 => "C compiler (VS 2008)",
        0x84 => "C++ compiler (VS 2008)",
        0x9b => "C compiler (VS 2010)",
        0x9c => "C++ compiler (VS 2010)",
        0xab => "C compiler (VS 2010 SP1)",
        0xb0 => "C compiler (VS 2012)",
        0xb1 => "C++ compiler (VS 2012)",
        0xc9 => "C compiler (VS 2013)",
        0xca => "C++ compiler (VS 2013)",
        0xe0 => "C compiler (VS 2015)",
        0xe1 => "C++ compiler (VS 2015)",
        0xff => "C compiler (VS 2017)",
        0x100 => "C++ compiler (VS 2017)",
        0x103 => "C/C++ compiler (VS 2019)",
        0x104 => "C/C++ compiler (VS 2019)",
        _ => $"id 0x{id:X}",
    };
}
