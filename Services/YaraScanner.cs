using System.Diagnostics;
using System.Globalization;

namespace BinaryExplorer.Services;

public sealed record YaraStringMatch(long Offset, string Identifier, string Data);

public sealed record YaraMatch(string Rule, List<string> Tags, List<YaraStringMatch> Strings);

public sealed class YaraScanResult
{
    public List<YaraMatch> Matches { get; } = new();
    public string? Error { get; init; }
    public TimeSpan Duration { get; init; }
}

public static class YaraScanner
{
    public static async Task<YaraScanResult> ScanAsync(
        string yaraExePath,
        string rulesPath,
        string targetBinaryPath,
        CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = yaraExePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-s");      // print strings
        psi.ArgumentList.Add("-g");      // print tags
        psi.ArgumentList.Add("-r");      // recursive if rulesPath is a directory
        psi.ArgumentList.Add(rulesPath);
        psi.ArgumentList.Add(targetBinaryPath);

        var sw = Stopwatch.StartNew();
        Process proc;
        try
        {
            proc = Process.Start(psi)
                ?? throw new InvalidOperationException("yara.exe could not be started.");
        }
        catch (Exception ex)
        {
            return new YaraScanResult
            {
                Error = $"Could not start '{yaraExePath}': {ex.Message}",
                Duration = sw.Elapsed,
            };
        }

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);

        if (!await WaitForExitAsync(proc, TimeSpan.FromMinutes(2), ct))
        {
            try { proc.Kill(); } catch { }
            return new YaraScanResult { Error = "yara.exe timed out (>2 min).", Duration = sw.Elapsed };
        }

        string stdout = await stdoutTask;
        string stderr = await stderrTask;
        sw.Stop();

        var result = new YaraScanResult { Duration = sw.Elapsed };
        if (proc.ExitCode != 0 && !string.IsNullOrWhiteSpace(stderr))
        {
            return new YaraScanResult
            {
                Error = stderr.Trim(),
                Duration = sw.Elapsed,
            };
        }

        ParseOutput(stdout, result.Matches);
        return result;
    }

    private static async Task<bool> WaitForExitAsync(Process proc, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await proc.WaitForExitAsync(cts.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static void ParseOutput(string output, List<YaraMatch> sink)
    {
        YaraMatch? current = null;
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r', '\n');
            if (line.Length == 0) continue;

            // YARA -s output format:
            //   rulename [tag1,tag2] /path/to/file       (header line)
            //   0xOFFSET:$ident: data                    (string match line — with -s)
            if (line.StartsWith("0x", StringComparison.Ordinal))
            {
                if (current is null) continue;
                int colon1 = line.IndexOf(':');
                if (colon1 < 0) continue;
                if (!long.TryParse(line.AsSpan(2, colon1 - 2), NumberStyles.HexNumber, null, out long offset))
                    continue;
                int colon2 = line.IndexOf(':', colon1 + 1);
                string ident = colon2 < 0 ? line[(colon1 + 1)..] : line[(colon1 + 1)..colon2];
                string data  = colon2 < 0 ? "" : line[(colon2 + 1)..].TrimStart();
                if (data.Length > 200) data = data[..200] + "…";
                current.Strings.Add(new YaraStringMatch(offset, ident.Trim(), data));
            }
            else
            {
                // Header line. Could be: "rule path" or "rule [tags] path".
                int firstSpace = line.IndexOf(' ');
                if (firstSpace < 0) continue;
                string rule = line[..firstSpace];
                List<string> tags = new();
                string rest = line[(firstSpace + 1)..];
                if (rest.StartsWith('['))
                {
                    int closeBracket = rest.IndexOf(']');
                    if (closeBracket > 1)
                    {
                        var tagStr = rest.Substring(1, closeBracket - 1);
                        tags = tagStr.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
                    }
                }
                current = new YaraMatch(rule, tags, new List<YaraStringMatch>());
                sink.Add(current);
            }
        }
    }
}
