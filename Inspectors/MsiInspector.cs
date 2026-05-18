using BinaryExplorer.Core;
using BinaryExplorer.Services.Mcp;

namespace BinaryExplorer.Inspectors;

public sealed class MsiInspector : IBinaryInspector
{
    public string Name => "MSI";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            if (!MsiQuery.IsCompoundFileBinary(context.Bytes))
            {
                findings.Add(new Finding(
                    "File type",
                    "Not a Compound File Binary",
                    "MSI / DOC / DB files start with D0 CF 11 E0 A1 B1 1A E1. This file does not, so MSI inspection is skipped."));
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Not an MSI",
                    Findings = findings,
                };
            }

            try
            {
                var props = MsiQuery.ReadProperties(context.Path);
                if (props is null)
                {
                    findings.Add(new Finding(
                        "MSI",
                        "Couldn't open Property table",
                        "WindowsInstaller COM either failed or this CFB isn't an MSI installer database.",
                        Severity.Warning));
                    return new InspectionResult { InspectorName = Name, Headline = "MSI parse failed", Findings = findings };
                }

                string Get(string key) => props.TryGetValue(key, out var v) && v is not null ? v : "(not set)";

                findings.Add(new Finding("ProductName",    Get("ProductName")));
                findings.Add(new Finding("ProductVersion", Get("ProductVersion")));
                findings.Add(new Finding("ProductCode",    Get("ProductCode")));
                findings.Add(new Finding("UpgradeCode",    Get("UpgradeCode")));
                findings.Add(new Finding("Manufacturer",   Get("Manufacturer")));
                findings.Add(new Finding("ProductLanguage",Get("ProductLanguage")));
                if (props.TryGetValue("ARPCONTACT",      out var c1) && !string.IsNullOrEmpty(c1)) findings.Add(new Finding("ARPCONTACT",      c1));
                if (props.TryGetValue("ARPURLINFOABOUT", out var c2) && !string.IsNullOrEmpty(c2)) findings.Add(new Finding("ARPURLINFOABOUT", c2));
                if (props.TryGetValue("ARPHELPLINK",     out var c3) && !string.IsNullOrEmpty(c3)) findings.Add(new Finding("ARPHELPLINK",     c3));

                int? files          = MsiQuery.CountRows(context.Path, "File");
                int? registry       = MsiQuery.CountRows(context.Path, "Registry");
                int? shortcuts      = MsiQuery.CountRows(context.Path, "Shortcut");
                int? features       = MsiQuery.CountRows(context.Path, "Feature");
                int? components     = MsiQuery.CountRows(context.Path, "Component");
                int? customActions  = MsiQuery.CountRows(context.Path, "CustomAction");
                int? launchConds    = MsiQuery.CountRows(context.Path, "LaunchCondition");
                int? media          = MsiQuery.CountRows(context.Path, "Media");

                string Format(int? n) => n is null ? "(table missing or unreadable)" : n.Value.ToString();
                findings.Add(new Finding("Files",            Format(files)));
                findings.Add(new Finding("Components",       Format(components)));
                findings.Add(new Finding("Features",         Format(features)));
                findings.Add(new Finding("Registry entries", Format(registry)));
                findings.Add(new Finding("Shortcuts",        Format(shortcuts)));
                findings.Add(new Finding("Media cabinets",   Format(media)));
                findings.Add(new Finding(
                    "Custom actions",
                    Format(customActions),
                    customActions is > 0
                        ? "CustomAction rows run arbitrary code during install. Worth inspecting via the MCP 'query_msi_table' tool with table='CustomAction'."
                        : null,
                    customActions is > 0 ? Severity.Warning : Severity.Info));
                findings.Add(new Finding("LaunchConditions", Format(launchConds)));

                string headline = $"MSI: {Get("ProductName")} {Get("ProductVersion")}";
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
                    Headline = "MSI inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }
}
