using System.Reflection.PortableExecutable;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class TlsCallbacksInspector : IBinaryInspector
{
    public string Name => "TLS";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var ms = new MemoryStream(context.Bytes, writable: false);
                using var pe = new PEReader(ms);

                var dir = pe.PEHeaders.PEHeader?.ThreadLocalStorageTableDirectory;
                if (dir is null || dir.Value.Size == 0)
                {
                    findings.Add(new Finding("TLS directory", "Not present"));
                    return new InspectionResult { InspectorName = Name, Headline = "No TLS callbacks", Findings = findings };
                }

                bool pe32Plus = pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus;
                ulong imageBase = pe.PEHeaders.PEHeader!.ImageBase;
                int ptrSize = pe32Plus ? 8 : 4;

                if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int tlsOff))
                {
                    findings.Add(new Finding("TLS directory", "RVA unresolved"));
                    return new InspectionResult { InspectorName = Name, Headline = "TLS RVA unresolved", Findings = findings };
                }

                // IMAGE_TLS_DIRECTORY layout:
                //   StartAddressOfRawData (ptr)
                //   EndAddressOfRawData   (ptr)
                //   AddressOfIndex        (ptr)
                //   AddressOfCallBacks    (ptr)
                //   SizeOfZeroFill        (uint32)
                //   Characteristics       (uint32)
                int p = tlsOff + ptrSize * 3;
                ulong cbVa = ptrSize == 8
                    ? BitConverter.ToUInt64(context.Bytes, p)
                    : BitConverter.ToUInt32(context.Bytes, p);
                findings.Add(new Finding("AddressOfCallBacks", $"0x{cbVa:X}"));

                if (cbVa == 0)
                {
                    findings.Add(new Finding("Callbacks", "None"));
                    return new InspectionResult { InspectorName = Name, Headline = "TLS table present, no callbacks", Findings = findings };
                }

                if (cbVa < imageBase || cbVa - imageBase > int.MaxValue)
                {
                    findings.Add(new Finding("Callbacks", "(VA out of range)"));
                    return new InspectionResult { InspectorName = Name, Headline = "TLS callback VA unresolvable", Findings = findings };
                }
                int cbRva = (int)(cbVa - imageBase);
                if (!LanguageInspector.TryRvaToOffset(pe, cbRva, out int cbOff))
                {
                    findings.Add(new Finding("Callbacks", "(RVA unresolvable)"));
                    return new InspectionResult { InspectorName = Name, Headline = "TLS callback RVA unresolvable", Findings = findings };
                }

                int callbackCount = 0;
                while (cbOff + ptrSize <= context.Bytes.Length && callbackCount < 64)
                {
                    ulong fnVa = ptrSize == 8
                        ? BitConverter.ToUInt64(context.Bytes, cbOff)
                        : BitConverter.ToUInt32(context.Bytes, cbOff);
                    if (fnVa == 0) break;
                    long fnRva = (long)fnVa - (long)imageBase;
                    findings.Add(new Finding(
                        $"Callback [{callbackCount}]",
                        $"VA 0x{fnVa:X16}",
                        fnRva is >= 0 and <= int.MaxValue ? $"RVA 0x{fnRva:X}" : null,
                        Severity.Warning));
                    callbackCount++;
                    cbOff += ptrSize;
                }

                if (callbackCount == 0)
                    findings.Add(new Finding("Callbacks", "None (empty list)"));

                string headline = callbackCount > 0
                    ? $"{callbackCount} TLS callback(s) — code runs before main"
                    : "TLS table present, no callbacks";

                return new InspectionResult { InspectorName = Name, Headline = headline, Findings = findings };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "TLS callbacks inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }
}
