using System.Text;
using BinaryExplorer.Core;

namespace BinaryExplorer.Services;

public static class ReportExporter
{
    public static string BuildMarkdown()
    {
        var sb = new StringBuilder();
        var ctx = AppState.Instance.Binary;
        if (ctx is null)
        {
            sb.AppendLine("# BinaryExplorer report");
            sb.AppendLine();
            sb.AppendLine("_No file loaded._");
            return sb.ToString();
        }

        sb.AppendLine($"# {System.IO.Path.GetFileName(ctx.Path)}");
        sb.AppendLine();
        sb.AppendLine($"- **Path**: `{ctx.Path}`");
        sb.AppendLine($"- **Size**: {ctx.Bytes.LongLength:N0} bytes");
        sb.AppendLine($"- **Generated**: {DateTimeOffset.UtcNow:u}");
        sb.AppendLine();

        // Group by inspector in a stable order.
        var preferred = new[]
        {
            "Language", "VersionInfo", "Signature", "Hashes",
            "RichHeader", "Debug",
            "ETW", "Dependencies", "Capabilities", "Strings", "TLS",
            "PE", "Packing", "Embedded",
            "MOTW", "VirusTotal",
        };
        var present = AppState.Instance.Results;

        foreach (var name in preferred)
        {
            if (!present.TryGetValue(name, out var result)) continue;
            AppendInspector(sb, result);
        }
        foreach (var kv in present.OrderBy(k => k.Key))
        {
            if (preferred.Contains(kv.Key)) continue;
            AppendInspector(sb, kv.Value);
        }

        return sb.ToString();
    }

    private static void AppendInspector(StringBuilder sb, InspectionResult result)
    {
        sb.AppendLine($"## {result.InspectorName}");
        if (!string.IsNullOrEmpty(result.Headline))
            sb.AppendLine($"_{result.Headline}_");
        if (!string.IsNullOrEmpty(result.Error))
        {
            sb.AppendLine();
            sb.AppendLine("> **Error:** " + result.Error);
        }
        sb.AppendLine();
        if (result.Findings.Count > 0)
        {
            sb.AppendLine("| Title | Value |");
            sb.AppendLine("| --- | --- |");
            foreach (var f in result.Findings)
            {
                string val = (f.Value ?? "").Replace("|", "\\|").Replace("\n", "<br>");
                string title = f.Title.Replace("|", "\\|");
                sb.AppendLine($"| {title} | {val} |");
            }
            // Details block (multi-line) for findings that had Details.
            bool anyDetails = result.Findings.Any(f => !string.IsNullOrEmpty(f.Details));
            if (anyDetails)
            {
                sb.AppendLine();
                sb.AppendLine("<details><summary>Details</summary>");
                sb.AppendLine();
                foreach (var f in result.Findings)
                {
                    if (string.IsNullOrEmpty(f.Details)) continue;
                    sb.AppendLine($"**{f.Title}**");
                    sb.AppendLine();
                    sb.AppendLine("```");
                    sb.AppendLine(f.Details);
                    sb.AppendLine("```");
                    sb.AppendLine();
                }
                sb.AppendLine("</details>");
            }
        }
        sb.AppendLine();
    }
}
