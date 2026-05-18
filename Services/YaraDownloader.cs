using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text.Json;

namespace BinaryExplorer.Services;

public static class YaraDownloader
{
    private const string GitHubApiUrl = "https://api.github.com/repos/VirusTotal/yara/releases/latest";

    public static async Task<string> DownloadLatestAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report("Querying GitHub for latest YARA release...");
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("BinaryExplorer/1.0 (+https://github.com/guscatalano/BinaryExplorer)");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

        using var apiResp = await http.GetAsync(GitHubApiUrl, ct).ConfigureAwait(false);
        if (!apiResp.IsSuccessStatusCode)
            throw new InvalidOperationException($"GitHub API returned {(int)apiResp.StatusCode}: {await apiResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false)}");

        var json = await apiResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);
        string tag = doc.RootElement.TryGetProperty("tag_name", out var tagEl) ? tagEl.GetString() ?? "?" : "?";

        // Find a win64 .zip asset.
        string? downloadUrl = null;
        string? assetName = null;
        if (doc.RootElement.TryGetProperty("assets", out var assetsEl) && assetsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var asset in assetsEl.EnumerateArray())
            {
                string name = asset.GetProperty("name").GetString() ?? "";
                if (!name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) continue;
                if (!name.Contains("win64", StringComparison.OrdinalIgnoreCase)) continue;
                downloadUrl = asset.GetProperty("browser_download_url").GetString();
                assetName = name;
                break;
            }
        }
        if (downloadUrl is null)
            throw new InvalidOperationException("Couldn't find a win64 .zip asset in the latest release.");

        progress?.Report($"Downloading {assetName} ({tag})...");
        byte[] zipBytes;
        using (var zipResp = await http.GetAsync(downloadUrl, ct).ConfigureAwait(false))
        {
            zipResp.EnsureSuccessStatusCode();
            zipBytes = await zipResp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        }

        var targetDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BinaryExplorer", "yara");
        Directory.CreateDirectory(targetDir);

        progress?.Report($"Extracting {zipBytes.Length:N0} bytes to {targetDir}...");
        using (var ms = new MemoryStream(zipBytes))
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Read))
        {
            foreach (var entry in zip.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name)) continue; // directory entry
                string safeName = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                string dest = Path.GetFullPath(Path.Combine(targetDir, safeName));
                // Defensive: keep extraction inside targetDir.
                if (!dest.StartsWith(targetDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                    !dest.Equals(targetDir, StringComparison.OrdinalIgnoreCase))
                    continue;
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                entry.ExtractToFile(dest, overwrite: true);
            }
        }

        // Prefer yara64.exe, fall back to yara.exe.
        var candidates = new[] { "yara64.exe", "yara.exe" };
        foreach (var name in candidates)
        {
            var found = Directory.GetFiles(targetDir, name, SearchOption.AllDirectories).FirstOrDefault();
            if (found is not null)
            {
                progress?.Report($"Installed YARA at {found}");
                return found;
            }
        }
        throw new InvalidOperationException("Extracted archive, but no yara64.exe / yara.exe found inside.");
    }
}
