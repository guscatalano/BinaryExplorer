using System.Diagnostics;
using System.IO;
using BinaryExplorer.Core;

namespace BinaryExplorer.Services;

public static class EmbeddedExtractor
{
    public static string TempRoot
    {
        get
        {
            var root = Path.Combine(Path.GetTempPath(), "BinaryExplorer");
            Directory.CreateDirectory(root);
            return root;
        }
    }

    public static async Task<string> ExtractAsync(BinaryContext context, EmbeddedHit hit, CancellationToken ct = default)
    {
        long size = hit.EffectiveSize(context.Bytes.LongLength);
        if (size <= 0 || hit.Offset >= context.Bytes.LongLength)
            throw new InvalidOperationException("Invalid offset/size for extraction.");

        string stem = Path.GetFileNameWithoutExtension(context.Path);
        string sanitizedType = SanitizeForFilename(hit.Type);
        string fileName = $"{stem}_+{hit.Offset:X8}_{sanitizedType}{hit.SuggestedExtension}";
        string outPath = Path.Combine(TempRoot, fileName);

        await using var output = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true);
        await output.WriteAsync(context.Bytes.AsMemory((int)hit.Offset, (int)size), ct).ConfigureAwait(false);
        return outPath;
    }

    public static void RevealInExplorer(string path)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"/select,\"{path}\"",
            UseShellExecute = true,
        });
    }

    public static void OpenWithDefaultHandler(string path)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true,
        });
    }

    private static string SanitizeForFilename(string input)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new System.Text.StringBuilder(input.Length);
        foreach (var c in input)
            sb.Append(Array.IndexOf(invalid, c) >= 0 || c == ' ' || c == '/' ? '_' : c);
        return sb.ToString();
    }
}
