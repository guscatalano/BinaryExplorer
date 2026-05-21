using System.ComponentModel;
using System.Text;
using BinaryExplorer.Inspectors;
using BinaryExplorer.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace BinaryExplorer.Pages;

public sealed partial class ResourcesPage : Page
{
    private List<ResourceEntry> _entries = new();
    private string? _loadedPath;
    private ResourceEntry? _selected;

    public ResourcesPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged += OnStateChanged;
        Refresh();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged -= OnStateChanged;
    }

    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        DispatcherQueue.TryEnqueue(Refresh);
    }

    private void Refresh()
    {
        var ctx = AppState.Instance.Binary;
        if (ctx is null)
        {
            HeadlineText.Text = "No file loaded.";
            ResTree.RootNodes.Clear();
            ShowText("Open a file on the Overview page first.");
            _loadedPath = null;
            return;
        }
        if (_loadedPath == ctx.Path) return;

        _entries = PeResources.Walk(ctx.Bytes);
        _loadedPath = ctx.Path;

        ResTree.RootNodes.Clear();
        if (_entries.Count == 0)
        {
            HeadlineText.Text = "No resource directory found.";
            ShowText("This binary has no PE resource section, or it's empty.");
            return;
        }
        HeadlineText.Text = $"{_entries.Count} resource(s) across {_entries.GroupBy(r => r.TypeDisplay).Count()} type(s)";

        // Build Type -> Name -> Language tree.
        foreach (var typeGroup in _entries.GroupBy(r => r.TypeDisplay).OrderBy(g => g.Key))
        {
            var typeNode = new TreeViewNode
            {
                Content = new TreeNodeTag(typeGroup.Key, NodeKind.Type, null),
                IsExpanded = false,
            };
            foreach (var nameGroup in typeGroup.GroupBy(r => r.NameDisplay).OrderBy(g => g.Key))
            {
                var nameNode = new TreeViewNode
                {
                    Content = new TreeNodeTag(nameGroup.Key, NodeKind.Name, null),
                };
                foreach (var entry in nameGroup.OrderBy(r => r.Language))
                {
                    var leaf = new TreeViewNode
                    {
                        Content = new TreeNodeTag(
                            $"lang 0x{entry.Language:X4}  ({EmbeddedHitFormat(entry.Size)})",
                            NodeKind.Leaf,
                            entry),
                    };
                    nameNode.Children.Add(leaf);
                }
                typeNode.Children.Add(nameNode);
            }
            ResTree.RootNodes.Add(typeNode);
        }

        ShowText("Pick a resource on the left to view it.");
    }

    private void ResTree_ItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
    {
        if (args.InvokedItem is not TreeViewNode node) return;
        if (node.Content is not TreeNodeTag tag) return;
        if (tag.Kind != NodeKind.Leaf || tag.Entry is null) return;

        var entry = tag.Entry;
        var ctx = AppState.Instance.Binary;
        if (ctx is null) return;

        _selected = entry;
        ExtractBtn.IsEnabled = true;
        ResHeader.Text = $"{entry.TypeDisplay} / {entry.NameDisplay}";
        ResSubHeader.Text = $"lang 0x{entry.Language:X4}  ·  +0x{entry.FileOffset:X8}  ·  {EmbeddedHitFormat(entry.Size)}";

        // Slice the resource bytes.
        var slice = new byte[entry.Size];
        Array.Copy(ctx.Bytes, entry.FileOffset, slice, 0, entry.Size);

        switch (entry.TypeId)
        {
            case 24:   // RT_MANIFEST → UTF-8 XML
            case 23:   // RT_HTML
                ShowText(PrettyPrintXmlOrText(slice));
                break;
            case 6:    // RT_STRING
                ShowText(FormatStringTable(slice, entry.NameId));
                break;
            default:
                ShowHex(slice, entry.FileOffset);
                break;
        }
    }

    private void ShowText(string text)
    {
        TextPane.Text = text;
        TextScroller.Visibility = Visibility.Visible;
        HexPane.Visibility = Visibility.Collapsed;
    }

    private void ShowHex(byte[] bytes, int baseOff)
    {
        HexPane.Bytes = bytes;
        HexPane.BaseOffset = baseOff;
        HexPane.Skip = 0;
        HexPane.MaxBytes = 64 * 1024;
        HexPane.Visibility = Visibility.Visible;
        TextScroller.Visibility = Visibility.Collapsed;
    }

    private static string PrettyPrintXmlOrText(byte[] bytes)
    {
        if (bytes.Length == 0) return "(empty)";
        // Try UTF-8 with BOM detection. Manifests are often UTF-8 with no BOM.
        int start = 0;
        Encoding enc = Encoding.UTF8;
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) start = 3;
        else if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) { enc = Encoding.Unicode; start = 2; }
        else if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) { enc = Encoding.BigEndianUnicode; start = 2; }
        string raw = enc.GetString(bytes, start, bytes.Length - start).Trim();
        try
        {
            var doc = System.Xml.Linq.XDocument.Parse(raw);
            return doc.ToString();
        }
        catch
        {
            return raw;
        }
    }

    private static string FormatStringTable(byte[] bytes, int? bundleId)
    {
        // RT_STRING bundles contain 16 strings; each is a UTF-16 length-prefixed string (count of WCHARs).
        // String IDs in this bundle: ((bundleId - 1) * 16) ... ((bundleId - 1) * 16 + 15).
        var sb = new StringBuilder();
        int baseId = bundleId.HasValue ? (bundleId.Value - 1) * 16 : 0;
        int p = 0;
        for (int i = 0; i < 16; i++)
        {
            if (p + 2 > bytes.Length) break;
            ushort len = BitConverter.ToUInt16(bytes, p);
            p += 2;
            if (p + len * 2 > bytes.Length) break;
            if (len == 0) { sb.AppendLine($"#{baseId + i}: (empty)"); continue; }
            string s = Encoding.Unicode.GetString(bytes, p, len * 2);
            sb.AppendLine($"#{baseId + i}: {s}");
            p += len * 2;
        }
        return sb.ToString();
    }

    private static string EmbeddedHitFormat(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024):F1} MB";
    }

    private async void ExtractBtn_Click(object sender, RoutedEventArgs e)
    {
        var entry = _selected;
        var ctx = AppState.Instance.Binary;
        if (entry is null || ctx is null) return;

        ExtractBtn.IsEnabled = false;
        try
        {
            string stem = System.IO.Path.GetFileNameWithoutExtension(ctx.Path);
            string typeTag = SanitizeForFilename(entry.TypeDisplay);
            string nameTag = SanitizeForFilename(entry.NameDisplay);
            string ext = ResourceExtension(entry, ctx.Bytes);
            string fileName = $"{stem}_{typeTag}_{nameTag}_lang{entry.Language:X4}{ext}";
            string outDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "BinaryExplorer");
            System.IO.Directory.CreateDirectory(outDir);
            string outPath = System.IO.Path.Combine(outDir, fileName);

            await using (var fs = System.IO.File.Create(outPath))
                await fs.WriteAsync(ctx.Bytes.AsMemory(entry.FileOffset, entry.Size));

            var dlg = new ContentDialog
            {
                Title = "Resource extracted",
                Content = new TextBlock { Text = outPath, IsTextSelectionEnabled = true, TextWrapping = TextWrapping.Wrap, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas") },
                PrimaryButtonText = "Open folder",
                CloseButtonText = "OK",
                XamlRoot = XamlRoot,
            };
            var result = await dlg.ShowAsync();
            if (result == ContentDialogResult.Primary)
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{outPath}\"",
                    UseShellExecute = true,
                });
            }
        }
        catch (Exception ex)
        {
            var dlg = new ContentDialog
            {
                Title = "Extraction failed",
                Content = ex.Message,
                CloseButtonText = "OK",
                XamlRoot = XamlRoot,
            };
            await dlg.ShowAsync();
        }
        finally
        {
            ExtractBtn.IsEnabled = _selected is not null;
        }
    }

    private static string SanitizeForFilename(string s)
    {
        var invalid = System.IO.Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(Array.IndexOf(invalid, c) >= 0 || c == ' ' || c == '/' || c == '\\' ? '_' : c);
        return sb.ToString();
    }

    private static string ResourceExtension(ResourceEntry entry, byte[] full)
    {
        // Best-effort: pick extension from resource type, else sniff first bytes.
        switch (entry.TypeId)
        {
            case 1:  return ".cur";    // RT_CURSOR
            case 2:  return ".bmp";    // RT_BITMAP
            case 3:  return ".ico";    // RT_ICON
            case 6:  return ".strtab"; // RT_STRING
            case 12: return ".grpcur";
            case 14: return ".grpico";
            case 16: return ".vsi";    // RT_VERSION
            case 23: return ".html";
            case 24: return ".manifest";
        }
        if (entry.Size >= 4 && entry.FileOffset + 4 <= full.Length)
        {
            byte b0 = full[entry.FileOffset], b1 = full[entry.FileOffset + 1],
                 b2 = full[entry.FileOffset + 2], b3 = full[entry.FileOffset + 3];
            if (b0 == 0x4D && b1 == 0x5A) return ".bin"; // PE — keep as .bin so it's not auto-launched
            if (b0 == 0x50 && b1 == 0x4B && b2 == 0x03 && b3 == 0x04) return ".zip";
            if (b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47) return ".png";
            if (b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF) return ".jpg";
            if (b0 == 0x47 && b1 == 0x49 && b2 == 0x46) return ".gif";
            if (b0 == 0x1F && b1 == 0x8B) return ".gz";
            if (b0 == 0x4D && b1 == 0x53 && b2 == 0x43 && b3 == 0x46) return ".cab";
        }
        return ".bin";
    }

    private enum NodeKind { Type, Name, Leaf }
    private sealed class TreeNodeTag
    {
        public string Label { get; }
        public NodeKind Kind { get; }
        public ResourceEntry? Entry { get; }
        public TreeNodeTag(string label, NodeKind kind, ResourceEntry? entry)
        {
            Label = label; Kind = kind; Entry = entry;
        }
        public override string ToString() => Label;
    }
}
