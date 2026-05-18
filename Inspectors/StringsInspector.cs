using System.Text;
using System.Text.RegularExpressions;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed partial class StringsInspector : IBinaryInspector
{
    public string Name => "Strings";

    private const int MinAsciiLen = 6;
    private const int MinWideLen = 6;
    private const int MaxStringLen = 512;
    private const int PerCategoryCap = 100;

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                var strings = ExtractStrings(context.Bytes);
                var iocs = ClassifyIocs(strings);

                findings.Add(new Finding(
                    "Strings extracted",
                    strings.Count.ToString("N0"),
                    $"ASCII >= {MinAsciiLen} chars, UTF-16LE >= {MinWideLen} chars."));

                foreach (var kv in iocs.OrderByDescending(k => k.Value.Count))
                {
                    var samples = kv.Value.Take(PerCategoryCap).ToList();
                    string detail = string.Join("\n", samples);
                    if (kv.Value.Count > samples.Count)
                        detail += $"\n... and {kv.Value.Count - samples.Count} more";
                    findings.Add(new Finding(kv.Key, kv.Value.Count.ToString(), detail));
                }

                if (iocs.Count == 0)
                    findings.Add(new Finding("IOCs", "None detected in extracted strings"));

                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = $"{strings.Count:N0} strings, {iocs.Values.Sum(l => l.Count)} IOC matches across {iocs.Count} categories",
                    Findings = findings,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Strings inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static List<string> ExtractStrings(byte[] bytes)
    {
        var result = new List<string>();
        // ASCII pass.
        int start = -1;
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            bool printable = b >= 0x20 && b < 0x7F;
            if (printable)
            {
                if (start < 0) start = i;
            }
            else
            {
                if (start >= 0 && i - start >= MinAsciiLen && i - start <= MaxStringLen)
                    result.Add(Encoding.ASCII.GetString(bytes, start, i - start));
                start = -1;
            }
        }
        if (start >= 0 && bytes.Length - start >= MinAsciiLen && bytes.Length - start <= MaxStringLen)
            result.Add(Encoding.ASCII.GetString(bytes, start, bytes.Length - start));

        // UTF-16LE pass.
        start = -1;
        for (int i = 0; i + 1 < bytes.Length; i += 2)
        {
            byte lo = bytes[i], hi = bytes[i + 1];
            bool printable = hi == 0 && lo >= 0x20 && lo < 0x7F;
            if (printable)
            {
                if (start < 0) start = i;
            }
            else
            {
                if (start >= 0)
                {
                    int charCount = (i - start) / 2;
                    if (charCount >= MinWideLen && charCount <= MaxStringLen)
                        result.Add(Encoding.Unicode.GetString(bytes, start, i - start));
                }
                start = -1;
            }
        }
        return result;
    }

    private static readonly Regex RxUrl    = new(@"\bhttps?://[^\s""'<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RxIp     = new(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b", RegexOptions.Compiled);
    private static readonly Regex RxDomain = new(@"\b(?!\d+\.)(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|dev|gov|edu|co|uk|us|ru|cn|de|fr|jp|info|biz|xyz|top|club|online|site|store|app|cloud|ai|me)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RxRegHk  = new(@"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\""\r\n]+", RegexOptions.Compiled);
    private static readonly Regex RxRegSw  = new(@"\b(?:SOFTWARE|SYSTEM)\\[A-Za-z0-9_ \-\\.]+", RegexOptions.Compiled);
    private static readonly Regex RxPath   = new(@"[A-Za-z]:\\[^""\r\n<>|]{3,}", RegexOptions.Compiled);
    private static readonly Regex RxPipe   = new(@"\\\\\.\\pipe\\[A-Za-z0-9_\-]+", RegexOptions.Compiled);
    private static readonly Regex RxMutex  = new(@"\b(?:Global|Local|Session)\\[A-Za-z0-9_\-\{\}]+", RegexOptions.Compiled);
    private static readonly Regex RxGuid   = new(@"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?", RegexOptions.Compiled);
    private static readonly Regex RxEmail  = new(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled);
    private static readonly Regex RxBase64 = new(@"\b[A-Za-z0-9+/]{40,}={0,2}\b", RegexOptions.Compiled);
    private static readonly Regex RxOnion  = new(@"\b[a-z2-7]{16,56}\.onion\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static Dictionary<string, List<string>> ClassifyIocs(List<string> strings)
    {
        var result = new SortedDictionary<string, HashSet<string>>(StringComparer.Ordinal);
        void Add(string cat, string val)
        {
            if (val.Length > 256) return;
            if (!result.TryGetValue(cat, out var set)) result[cat] = set = new HashSet<string>(StringComparer.Ordinal);
            set.Add(val);
        }

        foreach (var s in strings)
        {
            foreach (Match m in RxUrl.Matches(s))    Add("URL", m.Value);
            foreach (Match m in RxOnion.Matches(s))  Add("Tor onion", m.Value);
            foreach (Match m in RxEmail.Matches(s))  Add("Email", m.Value);
            foreach (Match m in RxIp.Matches(s))     Add("IPv4", m.Value);
            foreach (Match m in RxRegHk.Matches(s))  Add("Registry path", m.Value);
            foreach (Match m in RxRegSw.Matches(s))  Add("Registry path", m.Value);
            foreach (Match m in RxPipe.Matches(s))   Add("Named pipe", m.Value);
            foreach (Match m in RxMutex.Matches(s))  Add("Mutex name", m.Value);
            foreach (Match m in RxGuid.Matches(s))   Add("GUID", m.Value);
            foreach (Match m in RxPath.Matches(s))   Add("File path", m.Value);
            foreach (Match m in RxBase64.Matches(s)) Add("Base64 blob", m.Value.Length > 80 ? m.Value[..80] + "..." : m.Value);
            foreach (Match m in RxDomain.Matches(s))
            {
                // Skip if this domain is part of an already-matched URL or email.
                if (s.IndexOf("://" + m.Value, StringComparison.OrdinalIgnoreCase) >= 0) continue;
                if (s.IndexOf("@" + m.Value, StringComparison.OrdinalIgnoreCase) >= 0) continue;
                Add("Domain", m.Value);
            }
        }
        return result.ToDictionary(kv => kv.Key, kv => kv.Value.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList());
    }
}
