using System.IO;
using System.Runtime.InteropServices;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class MarkOfTheWebInspector : IBinaryInspector
{
    public string Name => "MOTW";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                var streams = EnumerateAlternateDataStreams(context.Path);

                // Try to read Zone.Identifier specifically.
                string zoneStreamPath = context.Path + ":Zone.Identifier";
                string? zoneContent = null;
                try
                {
                    zoneContent = File.ReadAllText(zoneStreamPath);
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
                catch (IOException) { /* drive may not support ADS (e.g. FAT/exFAT) */ }
                catch (UnauthorizedAccessException) { }

                if (zoneContent is null)
                {
                    findings.Add(new Finding(
                        "Mark of the Web",
                        "Not present",
                        "No Zone.Identifier alternate data stream. File is treated as local-origin."));
                }
                else
                {
                    var ini = ParseIni(zoneContent);
                    int zoneId = -1;
                    if (ini.TryGetValue("ZoneId", out var z) && int.TryParse(z, out var parsedZ))
                        zoneId = parsedZ;

                    string zoneName = zoneId switch
                    {
                        0 => "Local Computer",
                        1 => "Local Intranet",
                        2 => "Trusted Sites",
                        3 => "Internet",
                        4 => "Restricted Sites",
                        _ => "Unknown",
                    };
                    Severity sev = zoneId >= 3 ? Severity.Warning : (zoneId >= 1 ? Severity.Info : Severity.Info);

                    findings.Add(new Finding(
                        "Mark of the Web",
                        $"ZoneId={zoneId} ({zoneName})",
                        "From Zone.Identifier ADS. Apps and Windows use this to decide whether to trigger SmartScreen / block-on-execution.",
                        sev));

                    if (ini.TryGetValue("ReferrerUrl", out var refUrl))
                        findings.Add(new Finding("Referrer URL", refUrl));
                    if (ini.TryGetValue("HostUrl", out var hostUrl))
                        findings.Add(new Finding("Host URL", hostUrl));
                    if (ini.TryGetValue("HostIpAddress", out var ip))
                        findings.Add(new Finding("Host IP", ip));
                    if (ini.TryGetValue("LastWriterPackageFamilyName", out var pkg))
                        findings.Add(new Finding("Writer package", pkg));
                    if (ini.TryGetValue("AppZoneId", out var appZone))
                        findings.Add(new Finding("AppZoneId", appZone));

                    findings.Add(new Finding(
                        "Zone.Identifier (raw)",
                        $"{zoneContent.Length} bytes",
                        zoneContent.Trim()));
                }

                if (streams.Count > 0)
                {
                    findings.Add(new Finding(
                        "Alternate data streams",
                        streams.Count.ToString(),
                        string.Join("\n", streams.Select(s => $"{s.Name}  ({s.Size:N0} bytes)"))));
                }
                else
                {
                    findings.Add(new Finding(
                        "Alternate data streams",
                        "None (besides the default unnamed stream)"));
                }

                string headline = zoneContent is null
                    ? "No Mark of the Web"
                    : $"MOTW present — Zone {(zoneContent.Contains("ZoneId=3") ? "3 (Internet)" : "tagged")}";

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
                    Headline = "MOTW inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static Dictionary<string, string> ParseIni(string text)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('[') || line.StartsWith(';') || line.StartsWith('#'))
                continue;
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            dict[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
        }
        return dict;
    }

    // ===== FindFirstStreamW / FindNextStreamW =====

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(
        string lpFileName,
        int InfoLevel,
        out WIN32_FIND_STREAM_DATA lpFindStreamData,
        int dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr hFindFile);

    private static readonly IntPtr InvalidHandle = new IntPtr(-1);

    public record StreamInfo(string Name, long Size);

    private static List<StreamInfo> EnumerateAlternateDataStreams(string path)
    {
        var results = new List<StreamInfo>();
        IntPtr h = FindFirstStreamW(path, 0, out var sd, 0);
        if (h == InvalidHandle) return results;
        try
        {
            do
            {
                // Stream name format: "::$DATA" for the default stream, ":Zone.Identifier:$DATA" for ADS.
                if (sd.cStreamName == "::$DATA") continue;
                string display = sd.cStreamName;
                if (display.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase))
                    display = display.Substring(0, display.Length - ":$DATA".Length);
                if (display.StartsWith(':')) display = display.Substring(1);
                results.Add(new StreamInfo(display, sd.StreamSize));
            } while (FindNextStreamW(h, out sd));
        }
        finally
        {
            FindClose(h);
        }
        return results;
    }
}
