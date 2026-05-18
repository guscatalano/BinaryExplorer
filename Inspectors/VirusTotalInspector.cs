using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using BinaryExplorer.Core;
using BinaryExplorer.Services;

namespace BinaryExplorer.Inspectors;

public sealed class VirusTotalInspector : IBinaryInspector
{
    public string Name => "VirusTotal";

    private static readonly HttpClient Http = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    public async Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        var findings = new List<Finding>();

        string sha256 = ComputeSha256(context.Bytes);
        findings.Add(new Finding("SHA-256", sha256));

        var key = Settings.VirusTotalApiKey;
        if (string.IsNullOrWhiteSpace(key))
        {
            return new InspectionResult
            {
                InspectorName = Name,
                Headline = "VirusTotal: not configured (set API key in Settings)",
                Findings = findings,
            };
        }

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
            req.Headers.Add("x-apikey", key);
            using var resp = await Http.SendAsync(req, ct).ConfigureAwait(false);

            if ((int)resp.StatusCode == 404)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "VirusTotal: hash not known to VT",
                    Findings = findings,
                };
            }
            if ((int)resp.StatusCode == 401)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "VirusTotal: 401 Unauthorized (bad API key)",
                    Findings = findings,
                    Error = "Check your API key in Settings.",
                };
            }
            if ((int)resp.StatusCode == 429)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "VirusTotal: 429 rate-limited (try again in a minute)",
                    Findings = findings,
                };
            }
            if (!resp.IsSuccessStatusCode)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = $"VirusTotal: HTTP {(int)resp.StatusCode}",
                    Findings = findings,
                    Error = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false),
                };
            }

            using var body = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(body, cancellationToken: ct).ConfigureAwait(false);

            var attrs = doc.RootElement.GetProperty("data").GetProperty("attributes");

            int harmless = GetInt(attrs, "last_analysis_stats", "harmless");
            int malicious = GetInt(attrs, "last_analysis_stats", "malicious");
            int suspicious = GetInt(attrs, "last_analysis_stats", "suspicious");
            int undetected = GetInt(attrs, "last_analysis_stats", "undetected");
            int timeout = GetInt(attrs, "last_analysis_stats", "timeout");
            int total = harmless + malicious + suspicious + undetected + timeout;

            findings.Add(new Finding(
                "Detections",
                $"{malicious + suspicious} / {total}",
                $"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}, Timeout: {timeout}",
                malicious > 0 ? Severity.Error : (suspicious > 0 ? Severity.Warning : Severity.Info)));

            if (attrs.TryGetProperty("last_analysis_date", out var lad) && lad.ValueKind == JsonValueKind.Number)
            {
                var when = DateTimeOffset.FromUnixTimeSeconds(lad.GetInt64()).UtcDateTime;
                findings.Add(new Finding("Last analyzed", when.ToString("u")));
            }
            if (attrs.TryGetProperty("meaningful_name", out var mn) && mn.ValueKind == JsonValueKind.String)
                findings.Add(new Finding("Meaningful name", mn.GetString() ?? ""));
            if (attrs.TryGetProperty("type_description", out var td) && td.ValueKind == JsonValueKind.String)
                findings.Add(new Finding("Type", td.GetString() ?? ""));
            if (attrs.TryGetProperty("size", out var sz) && sz.ValueKind == JsonValueKind.Number)
                findings.Add(new Finding("Size (VT)", sz.GetInt64().ToString("N0") + " bytes"));
            if (attrs.TryGetProperty("times_submitted", out var ts) && ts.ValueKind == JsonValueKind.Number)
                findings.Add(new Finding("Times submitted", ts.GetInt32().ToString()));

            if (attrs.TryGetProperty("last_analysis_results", out var results) && results.ValueKind == JsonValueKind.Object)
            {
                var flagging = new List<(string Engine, string Category, string Result)>();
                foreach (var prop in results.EnumerateObject())
                {
                    string category = prop.Value.TryGetProperty("category", out var c) ? c.GetString() ?? "" : "";
                    if (category == "malicious" || category == "suspicious")
                    {
                        string r = prop.Value.TryGetProperty("result", out var rr) && rr.ValueKind == JsonValueKind.String
                            ? rr.GetString() ?? "" : "";
                        flagging.Add((prop.Name, category, r));
                    }
                }
                if (flagging.Count > 0)
                {
                    findings.Add(new Finding(
                        "Flagging engines",
                        flagging.Count.ToString(),
                        string.Join("\n", flagging.Select(f => $"{f.Engine}: [{f.Category}] {f.Result}"))));
                }
            }

            string headline = malicious switch
            {
                > 0 => $"VT: {malicious} engines flag as malicious ({total} total)",
                _ when suspicious > 0 => $"VT: {suspicious} suspicious / {total} total",
                _ => $"VT: clean ({total} engines, 0 detections)",
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
                Headline = "VirusTotal lookup failed",
                Findings = findings,
                Error = ex.Message,
            };
        }
    }

    private static int GetInt(JsonElement parent, string a, string b)
    {
        if (parent.TryGetProperty(a, out var ae) && ae.TryGetProperty(b, out var be) && be.ValueKind == JsonValueKind.Number)
            return be.GetInt32();
        return 0;
    }

    private static string ComputeSha256(byte[] bytes)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
