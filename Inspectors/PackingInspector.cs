using System.Reflection.PortableExecutable;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class PackingInspector : IBinaryInspector
{
    public string Name => "Packing";

    private static readonly (string Pattern, string Packer)[] PackerSignatures = new[]
    {
        ("UPX0",      "UPX"),
        ("UPX1",      "UPX"),
        ("UPX2",      "UPX"),
        ("UPX!",      "UPX"),
        (".aspack",   "ASPack"),
        (".adata",    "ASPack"),
        (".Themida",  "Themida"),
        ("Themida",   "Themida"),
        (".vmp0",     "VMProtect"),
        (".vmp1",     "VMProtect"),
        (".vmp2",     "VMProtect"),
        (".enigma1",  "Enigma"),
        (".enigma2",  "Enigma"),
        (".petite",   "PEtite"),
        (".mpress1",  "MPRESS"),
        (".mpress2",  "MPRESS"),
        ("PEC2",      "PECompact"),
        (".nsp0",     "NsPack"),
        (".nsp1",     "NsPack"),
        (".nsp2",     "NsPack"),
        ("FSG!",      "FSG"),
        ("PEBundle",  "PEBundle"),
    };

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var ms = new MemoryStream(context.Bytes, writable: false);
                using var pe = new PEReader(ms);

                var detectedPackers = new HashSet<string>(StringComparer.Ordinal);
                var sections = pe.PEHeaders.SectionHeaders;

                foreach (var s in sections)
                {
                    foreach (var (pat, packer) in PackerSignatures)
                    {
                        if (s.Name.Equals(pat, StringComparison.Ordinal))
                            detectedPackers.Add(packer);
                    }
                }

                // Per-section entropy.
                var sectionEntropies = new List<(string Name, double Entropy, long Size)>();
                foreach (var s in sections)
                {
                    int off = s.PointerToRawData;
                    int sz = s.SizeOfRawData;
                    if (off < 0 || sz <= 0 || off + sz > context.Bytes.Length) continue;
                    double e = ShannonEntropy(context.Bytes, off, sz);
                    sectionEntropies.Add((s.Name, e, sz));
                }

                int highEntropyCount = sectionEntropies.Count(x => x.Entropy >= 7.0);
                double overall = ShannonEntropy(context.Bytes, 0, context.Bytes.Length);

                findings.Add(new Finding("Overall file entropy", overall.ToString("F3"),
                    "0 = uniform repetition; 8 = perfectly random. Compressed/encrypted data scores ~7.5+."));

                foreach (var (name, e, sz) in sectionEntropies)
                {
                    Severity sev = e >= 7.0 ? Severity.Warning : Severity.Info;
                    findings.Add(new Finding(
                        $"Section {name}",
                        $"entropy {e:F3}  ({EmbeddedHit.FormatBytes(sz)})",
                        e >= 7.0 ? "High — likely compressed or encrypted." : null,
                        sev));
                }

                if (detectedPackers.Count > 0)
                {
                    findings.Add(new Finding(
                        "Packer signatures",
                        string.Join(", ", detectedPackers),
                        "Section names match known packers.",
                        Severity.Warning));
                }
                else
                {
                    findings.Add(new Finding("Packer signatures", "None detected (by section name)"));
                }

                string headline = detectedPackers.Count > 0
                    ? $"Likely packed: {string.Join(", ", detectedPackers)}"
                    : highEntropyCount > 0
                        ? $"{highEntropyCount} high-entropy section(s) — possibly packed/encrypted"
                        : "No packing signals";

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
                    Headline = "Packing inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static double ShannonEntropy(byte[] data, int offset, int length)
    {
        if (length <= 0) return 0;
        Span<int> counts = stackalloc int[256];
        for (int i = 0; i < length; i++) counts[data[offset + i]]++;
        double entropy = 0;
        double invLen = 1.0 / length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] * invLen;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
