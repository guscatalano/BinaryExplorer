using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using BinaryExplorer.Inspectors;
using BinaryExplorer.Services;
using BinaryExplorer.Services.Mcp;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace BinaryExplorer.Pages;

public sealed partial class ToolsPage : Page
{
    public ToolsPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged += OnStateChanged;
        UpdateAvailability();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged -= OnStateChanged;
    }

    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        DispatcherQueue.TryEnqueue(UpdateAvailability);
    }

    private void UpdateAvailability()
    {
        bool hasFile = AppState.Instance.Binary is not null;
        XrefRunBtn.IsEnabled = hasFile;
        SearchRunBtn.IsEnabled = hasFile;
        StringRunBtn.IsEnabled = hasFile;
        StringRefRunBtn.IsEnabled = hasFile;
        DumpRunBtn.IsEnabled = hasFile;
        PeMapBtn.IsEnabled = hasFile;
        CallGraphBtn.IsEnabled = hasFile;
        InitSeqBtn.IsEnabled = hasFile;

        if (!hasFile)
        {
            HeadlineText.Text = "Open a file on the Overview page first. (GUID lookup works without a loaded binary.)";
        }
        else
        {
            HeadlineText.Text = "On-demand tools — same surface the MCP server exposes.";
        }
    }

    private string? CurrentPath => AppState.Instance.Binary?.Path;

    // ===================== GUID lookup =====================

    private async void GuidRunBtn_Click(object sender, RoutedEventArgs e)
    {
        var guids = (GuidInput.Text ?? "")
            .Split(new[] { '\n', '\r', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .Distinct()
            .ToArray();
        if (guids.Length == 0)
        {
            GuidResult.Text = "Paste one or more GUIDs on the left.";
            return;
        }
        GuidRunBtn.IsEnabled = false;
        GuidResult.Text = "Resolving...";
        try
        {
            var result = await McpTools.InvokeAsync("resolve_guid", new { guids });
            GuidResult.Text = PrettyJson(result);
        }
        catch (Exception ex)
        {
            GuidResult.Text = $"Error: {ex.Message}";
        }
        finally
        {
            GuidRunBtn.IsEnabled = true;
        }
    }

    private async void GuidUseEmbeddedBtn_Click(object sender, RoutedEventArgs e)
    {
        var ctx = AppState.Instance.Binary;
        if (ctx is null)
        {
            GuidResult.Text = "Open a file on the Overview page first.";
            return;
        }
        try
        {
            var inspector = new InterfacesInspector();
            var r = await inspector.InspectAsync(ctx);
            // The Interfaces inspector surfaces embedded GUIDs in findings.Value (RPC UUIDs, COM GUIDs).
            var found = new List<string>();
            foreach (var f in r.Findings)
            {
                string v = f.Value ?? "";
                // Pull anything that looks like a GUID with or without braces.
                foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(
                    v, @"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?"))
                {
                    found.Add(m.Value);
                }
            }
            found = found.Select(s => s.Trim('{', '}').ToUpperInvariant()).Distinct().ToList();
            if (found.Count == 0)
            {
                GuidResult.Text = "The COM/RPC inspector found no embedded GUIDs in this binary.";
                return;
            }
            GuidInput.Text = string.Join('\n', found.Select(g => "{" + g + "}"));
            GuidRunBtn_Click(sender, e);
        }
        catch (Exception ex)
        {
            GuidResult.Text = $"Error pulling embedded GUIDs: {ex.Message}";
        }
    }

    // ===================== Find xrefs =====================

    private async void XrefRunBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        string target = (XrefTarget.Text ?? "").Trim();
        if (target.Length == 0)
        {
            XrefResult.Text = "Enter a VA (0x140012345) or RVA (0x12345).";
            return;
        }
        XrefRunBtn.IsEnabled = false;
        XrefResult.Text = "Scanning...";
        try
        {
            int max = (int)XrefMax.Value;
            var result = await McpTools.InvokeAsync("find_xrefs", new { path, target, max });
            XrefResult.Text = FormatXrefResult(result);
        }
        catch (Exception ex)
        {
            XrefResult.Text = $"Error: {ex.Message}";
        }
        finally
        {
            XrefRunBtn.IsEnabled = true;
        }
    }

    private static string FormatXrefResult(object? result)
    {
        if (result is null) return "(no result)";
        try
        {
            using var doc = JsonDocument.Parse(JsonSerializer.Serialize(result));
            var root = doc.RootElement;
            var sb = new StringBuilder();
            if (root.TryGetProperty("error", out var err))
                return err.GetString() ?? "(error)";
            string targetVa = root.GetProperty("targetVa").GetString() ?? "?";
            string targetRva = root.GetProperty("targetRva").GetString() ?? "?";
            long scanned = root.GetProperty("instructionsScanned").GetInt64();
            int count = root.GetProperty("referenceCount").GetInt32();
            bool truncated = root.GetProperty("truncated").GetBoolean();
            sb.AppendLine($"target  VA {targetVa}  RVA {targetRva}");
            sb.AppendLine($"scanned {scanned:N0} instructions, {count} reference(s){(truncated ? "  [TRUNCATED]" : "")}");
            sb.AppendLine();
            foreach (var r in root.GetProperty("references").EnumerateArray())
            {
                string from = r.GetProperty("fromVa").GetString() ?? "?";
                string kind = r.GetProperty("kind").GetString() ?? "?";
                string section = r.GetProperty("section").GetString() ?? "?";
                string text = r.GetProperty("text").GetString() ?? "?";
                sb.AppendLine($"{from}  {section,-12}  {kind,-16}  {text}");
            }
            return sb.ToString();
        }
        catch
        {
            return PrettyJson(result);
        }
    }

    // ===================== Search bytes =====================

    private async void SearchRunBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        string pattern = (SearchPattern.Text ?? "").Trim();
        if (pattern.Length == 0)
        {
            SearchResult.Text = "Enter a hex or quoted-ASCII pattern.";
            return;
        }
        SearchRunBtn.IsEnabled = false;
        SearchResult.Text = "Searching...";
        try
        {
            int max = (int)SearchMax.Value;
            var result = await McpTools.InvokeAsync("search_bytes", new { path, pattern, max });
            SearchResult.Text = FormatSearchResult(result);
        }
        catch (Exception ex)
        {
            SearchResult.Text = $"Error: {ex.Message}";
        }
        finally
        {
            SearchRunBtn.IsEnabled = true;
        }
    }

    private static string FormatSearchResult(object? result)
    {
        try
        {
            using var doc = JsonDocument.Parse(JsonSerializer.Serialize(result));
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err)) return err.GetString() ?? "(error)";
            int patLen = root.GetProperty("patternLength").GetInt32();
            int count = root.GetProperty("matchCount").GetInt32();
            bool truncated = root.GetProperty("truncated").GetBoolean();
            var sb = new StringBuilder();
            sb.AppendLine($"pattern length {patLen} bytes, {count} hit(s){(truncated ? "  [TRUNCATED]" : "")}");
            sb.AppendLine();
            foreach (var o in root.GetProperty("offsets").EnumerateArray())
                sb.AppendLine(o.GetString());
            return sb.ToString();
        }
        catch
        {
            return PrettyJson(result);
        }
    }

    // ===================== Get string at =====================

    private async void StringRunBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        string offset = (StringOffset.Text ?? "").Trim();
        if (offset.Length == 0)
        {
            StringResult.Text = "Enter a file offset (0x... or decimal).";
            return;
        }
        StringRunBtn.IsEnabled = false;
        StringResult.Text = "Reading...";
        try
        {
            string encoding = (StringEncoding.SelectedItem as ComboBoxItem)?.Content as string ?? "auto";
            int maxLength = (int)StringMax.Value;
            var result = await McpTools.InvokeAsync("get_string_at", new { path, offset, encoding, maxLength });
            StringResult.Text = PrettyJson(result);
        }
        catch (Exception ex)
        {
            StringResult.Text = $"Error: {ex.Message}";
        }
        finally
        {
            StringRunBtn.IsEnabled = true;
        }
    }

    // ===================== Find string refs =====================

    private async void StringRefRunBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        string query = (StringRefInput.Text ?? "").Trim();
        if (query.Length == 0)
        {
            StringRefResult.Text = "Enter a string to look for.";
            return;
        }
        StringRefRunBtn.IsEnabled = false;
        StringRefResult.Text = "Searching...";
        try
        {
            string encoding = (StringRefEncoding.SelectedItem as ComboBoxItem)?.Content as string ?? "auto";
            int maxHits = (int)StringRefMaxHits.Value;
            int maxRefsPerHit = (int)StringRefMaxRefs.Value;
            bool resolveCodeRefs = StringRefResolve.IsChecked == true;
            var result = await McpTools.InvokeAsync("find_string_refs_ex", new
            {
                path, query, encoding, maxHits, maxRefsPerHit, resolveCodeRefs,
            });
            StringRefResult.Text = FormatStringRefResult(result);
        }
        catch (Exception ex)
        {
            StringRefResult.Text = $"Error: {ex.Message}";
        }
        finally
        {
            StringRefRunBtn.IsEnabled = true;
        }
    }

    private static string FormatStringRefResult(object? result)
    {
        try
        {
            using var doc = JsonDocument.Parse(JsonSerializer.Serialize(result));
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err)) return err.GetString() ?? "(error)";

            var sb = new StringBuilder();
            int hitCount = root.TryGetProperty("hitCount", out var hc) ? hc.GetInt32() : 0;
            bool hitsTruncated = root.TryGetProperty("hitsTruncated", out var ht) && ht.GetBoolean();
            sb.AppendLine($"{hitCount} hit(s){(hitsTruncated ? "  [TRUNCATED]" : "")}");
            sb.AppendLine();
            foreach (var h in root.GetProperty("hits").EnumerateArray())
            {
                string fo = h.GetProperty("fileOffset").GetString() ?? "?";
                string? vaStr = h.TryGetProperty("va", out var ve) && ve.ValueKind == JsonValueKind.String ? ve.GetString() : null;
                string? rvaStr = h.TryGetProperty("rva", out var rvae) && rvae.ValueKind == JsonValueKind.String ? rvae.GetString() : null;
                string? section = h.TryGetProperty("section", out var se) && se.ValueKind == JsonValueKind.String ? se.GetString() : null;
                string enc = h.GetProperty("encoding").GetString() ?? "?";
                int refCount = h.GetProperty("refCount").GetInt32();
                bool refsTruncated = h.GetProperty("refsTruncated").GetBoolean();
                sb.AppendLine(
                    $"hit @ {fo}  va {vaStr ?? "?"}  rva {rvaStr ?? "?"}  section {section ?? "?"}  ({enc})  — {refCount} ref(s){(refsTruncated ? " [TRUNCATED]" : "")}");
                foreach (var r in h.GetProperty("refs").EnumerateArray())
                {
                    string rfo = r.GetProperty("refFileOffset").GetString() ?? "?";
                    string? rrva = r.GetProperty("refRva").ValueKind == JsonValueKind.String ? r.GetProperty("refRva").GetString() : null;
                    string? rsec = r.GetProperty("section").ValueKind == JsonValueKind.String ? r.GetProperty("section").GetString() : null;
                    sb.AppendLine($"    {rfo}  rva {rrva ?? "?"}  {rsec ?? ""}");
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }
        catch
        {
            return PrettyJson(result);
        }
    }

    // ===================== Dump section =====================

    private async void DumpRunBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        string section = (DumpSection.Text ?? "").Trim();
        if (section.Length == 0)
        {
            DumpResult.Text = "Enter a section name (e.g. .text) or 0-based index.";
            return;
        }
        DumpRunBtn.IsEnabled = false;
        DumpResult.Text = "Dumping...";
        try
        {
            var result = await McpTools.InvokeAsync("dump_section", new { path, section });
            DumpResult.Text = PrettyJson(result);
        }
        catch (Exception ex)
        {
            DumpResult.Text = $"Error: {ex.Message}";
        }
        finally
        {
            DumpRunBtn.IsEnabled = true;
        }
    }

    // ===================== Diagrams =====================

    private async void PeMapBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        DiagramResult.Text = "Generating...";
        try
        {
            var result = await McpTools.InvokeAsync("get_pe_map", new { path, format = "mermaid" });
            DiagramResult.Text = ExtractMermaid(result);
        }
        catch (Exception ex)
        {
            DiagramResult.Text = $"Error: {ex.Message}";
        }
    }

    private async void CallGraphBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        string rva = (DiagramRva.Text ?? "").Trim();
        int depth = (int)DiagramDepth.Value;
        depth = Math.Clamp(depth, 1, 8);
        DiagramResult.Text = "Generating...";
        try
        {
            bool resolveThunks = CgResolveThunks.IsChecked == true;
            bool includeTailCalls = CgIncludeTailCalls.IsChecked == true;
            bool followConditionalBranches = CgFollowCond.IsChecked == true;
            bool pruneImports = CgPruneImports.IsChecked == true;

            object args = string.IsNullOrEmpty(rva)
                ? new { path, depth, format = "mermaid",
                        resolveThunks, includeTailCalls, followConditionalBranches, pruneImports }
                : new { path, rva, depth, format = "mermaid",
                        resolveThunks, includeTailCalls, followConditionalBranches, pruneImports };
            var result = await McpTools.InvokeAsync("get_call_graph_ex", args);
            DiagramResult.Text = ExtractMermaid(result);
        }
        catch (Exception ex)
        {
            DiagramResult.Text = $"Error: {ex.Message}";
        }
    }

    private async void InitSeqBtn_Click(object sender, RoutedEventArgs e)
    {
        string? path = CurrentPath;
        if (path is null) return;
        string rva = (DiagramRva.Text ?? "").Trim();
        int depth = (int)DiagramDepth.Value;
        DiagramResult.Text = "Generating...";
        try
        {
            object args = string.IsNullOrEmpty(rva)
                ? new { path, depth, format = "mermaid" }
                : new { path, rva, depth, format = "mermaid" };
            var result = await McpTools.InvokeAsync("get_init_sequence", args);
            DiagramResult.Text = ExtractMermaid(result);
        }
        catch (Exception ex)
        {
            DiagramResult.Text = $"Error: {ex.Message}";
        }
    }

    private void DiagramCopyBtn_Click(object sender, RoutedEventArgs e)
    {
        string text = DiagramResult.Text ?? "";
        if (text.Length == 0) return;
        var dp = new DataPackage();
        dp.SetText(text);
        Clipboard.SetContent(dp);
    }

    private static string ExtractMermaid(object? result)
    {
        if (result is null) return "(no result)";
        try
        {
            using var doc = JsonDocument.Parse(JsonSerializer.Serialize(result));
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err)) return err.GetString() ?? "(error)";
            if (root.TryGetProperty("mermaid", out var m) && m.ValueKind == JsonValueKind.String)
                return m.GetString() ?? "";
            return PrettyJson(result);
        }
        catch
        {
            return PrettyJson(result);
        }
    }

    // ===================== helpers =====================

    private static string PrettyJson(object? o)
    {
        if (o is null) return "(no result)";
        try
        {
            return JsonSerializer.Serialize(o, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (Exception ex)
        {
            return $"<json error: {ex.Message}>";
        }
    }
}
