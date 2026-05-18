using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Text;
using BinaryExplorer.Analysis;
using BinaryExplorer.Core;
using BinaryExplorer.Inspectors;
using BinaryExplorer.Services;
using Iced.Intel;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace BinaryExplorer.Pages;

public sealed partial class DisassemblyPage : Page
{
    private string? _loadedPath;
    private int _bitness;
    private ulong _imageBase;
    private Dictionary<ulong, string> _symbolMap = new();
    private List<FunctionInfo> _allFunctions = new();

    private readonly Stack<NavState> _backStack = new();
    private readonly Stack<NavState> _forwardStack = new();
    private bool _suppressHistory; // set while we programmatically navigate

    public DisassemblyPage()
    {
        InitializeComponent();
        UpdateHistoryButtons();
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
        DispatcherQueue.TryEnqueue(() => _ = RefreshAsync());
    }

    private void Refresh() => _ = RefreshAsync();

    private async Task RefreshAsync()
    {
        var ctx = AppState.Instance.Binary;
        if (ctx is null)
        {
            HeadlineText.Text = "No file loaded.";
            StartCombo.ItemsSource = null;
            FunctionList.ItemsSource = null;
            _allFunctions.Clear();
            ShowStatusMessage("Open a file on the Overview page first.");
            _loadedPath = null;
            _backStack.Clear(); _forwardStack.Clear(); UpdateHistoryButtons();
            return;
        }
        if (_loadedPath == ctx.Path) return;

        try
        {
            using var ms = new MemoryStream(ctx.Bytes, writable: false);
            using var pe = new PEReader(ms);
            var opt = pe.PEHeaders.PEHeader;
            if (opt is null)
            {
                HeadlineText.Text = "Not a PE file.";
                ShowStatusMessage("Disassembly requires a PE executable.");
                _loadedPath = ctx.Path;
                return;
            }
            var machine = pe.PEHeaders.CoffHeader.Machine;
            if (machine != Machine.Amd64 && machine != Machine.I386)
            {
                HeadlineText.Text = $"Unsupported machine: {machine}";
                ShowStatusMessage("This page handles x86/x64 only. ARM64 / other architectures aren't supported in v1.");
                _loadedPath = ctx.Path;
                return;
            }
            _bitness = (opt.Magic == PEMagic.PE32Plus) ? 64 : 32;
            _imageBase = opt.ImageBase;

            HeadlineText.Text = $"{System.IO.Path.GetFileName(ctx.Path)} — {(_bitness == 64 ? "x64" : "x86")} — analyzing...";
            ShowStatusMessage("Analyzing binary for functions and cross-references...");
            _loadedPath = ctx.Path;

            // Off-thread analysis.
            var idx = await AppState.Instance.GetOrAnalyzeAsync();
            _allFunctions = idx.Functions.ToList();

            // Build symbol map from confirmed and discovered function names.
            _symbolMap.Clear();
            foreach (var f in _allFunctions)
                _symbolMap[_imageBase + f.Rva] = f.Name;

            // Populate sidebar.
            FunctionList.ItemsSource = _allFunctions;

            // Populate the start combo from confirmed functions only (smaller picks).
            var starts = _allFunctions
                .Where(f => f.Confirmed)
                .Select(f => new DisasmStart($"{f.Name}  (RVA 0x{f.Rva:X})", f.Rva))
                .ToList();
            StartCombo.ItemsSource = starts;
            StartCombo.DisplayMemberPath = nameof(DisasmStart.Label);

            int confirmedCount = _allFunctions.Count(f => f.Confirmed);
            int totalCount = _allFunctions.Count;
            HeadlineText.Text = $"{System.IO.Path.GetFileName(ctx.Path)} — {(_bitness == 64 ? "x64" : "x86")} — {totalCount} function(s), {confirmedCount} named";
            ShowStatusMessage($"Analysis complete. {totalCount} functions discovered ({confirmedCount} confirmed via export/entry/TLS). Pick one on the left or enter an RVA.");
            _backStack.Clear(); _forwardStack.Clear(); UpdateHistoryButtons();
        }
        catch (Exception ex)
        {
            HeadlineText.Text = "Disassembly setup failed.";
            ShowStatusMessage(ex.ToString());
            _loadedPath = null;
        }
    }

    private void StartCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (StartCombo.SelectedItem is DisasmStart s)
            OffsetInput.Text = "0x" + s.Rva.ToString("X");
    }

    private void FunctionList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FunctionList.SelectedItem is FunctionInfo f)
        {
            OffsetInput.Text = "0x" + f.Rva.ToString("X");
            _ = NavigateAsync(f.Rva, pushHistory: true);
        }
    }

    private void FunctionFilter_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
        var query = sender.Text?.Trim() ?? "";
        IEnumerable<FunctionInfo> filtered = _allFunctions;
        if (query.Length > 0)
            filtered = filtered.Where(f => f.Name.Contains(query, StringComparison.OrdinalIgnoreCase));
        FunctionList.ItemsSource = filtered.ToList();
    }

    private async void Go_Click(object sender, RoutedEventArgs e)
    {
        if (!TryParseOffset(OffsetInput.Text, out uint rva))
        {
            ShowStatus("Couldn't parse RVA. Use 0x prefix for hex (0x1234) or 0n for decimal.", InfoBarSeverity.Warning);
            return;
        }
        await NavigateAsync(rva, pushHistory: true);
    }

    private async Task NavigateAsync(uint rva, bool pushHistory)
    {
        var ctx = AppState.Instance.Binary;
        if (ctx is null) return;

        if (pushHistory && !_suppressHistory)
        {
            // Push current state if any.
            if (TryParseOffset(OffsetInput.Text, out uint currentRva) && currentRva != rva)
                _backStack.Push(new NavState(currentRva, (int)CountInput.Value, ModeFromCombo()));
            _forwardStack.Clear();
        }

        _suppressHistory = true;
        OffsetInput.Text = "0x" + rva.ToString("X");
        _suppressHistory = false;
        UpdateHistoryButtons();

        int count = Math.Clamp((int)CountInput.Value, 1, 4096);
        ShowStatus($"Disassembling {count} instruction(s) at RVA 0x{rva:X}...", InfoBarSeverity.Informational);
        try
        {
            string? startLabel = _symbolMap.TryGetValue(_imageBase + rva, out var n) ? n : null;
            DisasmMode mode = ModeFromCombo();
            var lines = await Task.Run(() => Disassemble(ctx.Bytes, rva, count, mode, startLabel));
            RenderLines(lines);
            StatusBar.IsOpen = false;
        }
        catch (Exception ex)
        {
            ShowStatus($"Disassembly failed: {ex.Message}", InfoBarSeverity.Error);
        }
    }

    private DisasmMode ModeFromCombo() => ModeCombo.SelectedIndex switch
    {
        1 => DisasmMode.MultipleFunctions,
        2 => DisasmMode.Raw,
        _ => DisasmMode.SingleFunction,
    };

    private async void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_backStack.Count == 0) return;
        var prev = _backStack.Pop();
        if (TryParseOffset(OffsetInput.Text, out uint currentRva))
            _forwardStack.Push(new NavState(currentRva, (int)CountInput.Value, ModeFromCombo()));
        ApplyNavState(prev);
        await NavigateAsync(prev.Rva, pushHistory: false);
    }

    private async void Forward_Click(object sender, RoutedEventArgs e)
    {
        if (_forwardStack.Count == 0) return;
        var next = _forwardStack.Pop();
        if (TryParseOffset(OffsetInput.Text, out uint currentRva))
            _backStack.Push(new NavState(currentRva, (int)CountInput.Value, ModeFromCombo()));
        ApplyNavState(next);
        await NavigateAsync(next.Rva, pushHistory: false);
    }

    private void ApplyNavState(NavState s)
    {
        _suppressHistory = true;
        OffsetInput.Text = "0x" + s.Rva.ToString("X");
        CountInput.Value = s.Count;
        ModeCombo.SelectedIndex = (int)s.Mode;
        _suppressHistory = false;
        UpdateHistoryButtons();
    }

    private void UpdateHistoryButtons()
    {
        BackButton.IsEnabled = _backStack.Count > 0;
        ForwardButton.IsEnabled = _forwardStack.Count > 0;
    }

    private static bool TryParseOffset(string? text, out uint value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return uint.TryParse(text.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out value);
        if (text.StartsWith("0n", StringComparison.OrdinalIgnoreCase))
            return uint.TryParse(text.AsSpan(2), out value);
        return uint.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out value);
    }

    public enum DisasmMode { SingleFunction, MultipleFunctions, Raw }

    private List<DisasmLine> Disassemble(byte[] bytes, uint rva, int count, DisasmMode mode, string? startLabel)
    {
        var lines = new List<DisasmLine>();
        using var ms = new MemoryStream(bytes, writable: false);
        using var pe = new PEReader(ms);
        if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int fileOff))
        {
            lines.Add(DisasmLine.Plain($"// RVA 0x{rva:X} doesn't map to any PE section."));
            return lines;
        }

        ulong startIp = _imageBase + rva;
        var formatter = new MasmFormatter();
        formatter.Options.DigitSeparator = "";
        formatter.Options.FirstOperandCharIndex = 8;

        var raws = new List<Instruction>();
        var functionStarts = new HashSet<ulong> { startIp };
        int produced = 0;
        int cursor = fileOff;

        while (produced < count && cursor < bytes.Length)
        {
            var subReader = new ByteArrayCodeReader(bytes, cursor, bytes.Length - cursor);
            var subDecoder = Iced.Intel.Decoder.Create(_bitness, subReader);
            subDecoder.IP = startIp + (ulong)(cursor - fileOff);

            bool ended = false;
            while (produced < count && cursor < bytes.Length)
            {
                subDecoder.Decode(out var instr);
                raws.Add(instr);
                cursor += instr.Length;
                produced++;
                if (instr.IsInvalid) { ended = true; break; }
                if (instr.FlowControl == FlowControl.Return)
                {
                    if (mode == DisasmMode.SingleFunction) return RenderFinal(bytes, fileOff, startIp, raws, functionStarts, formatter, startLabel, lines);
                    if (mode == DisasmMode.MultipleFunctions) { ended = true; break; }
                }
            }

            if (mode != DisasmMode.MultipleFunctions || !ended) break;
            while (cursor < bytes.Length && (bytes[cursor] == 0xCC || bytes[cursor] == 0x90))
                cursor++;
            if (cursor >= bytes.Length || produced >= count) break;
            functionStarts.Add(startIp + (ulong)(cursor - fileOff));
        }

        return RenderFinal(bytes, fileOff, startIp, raws, functionStarts, formatter, startLabel, lines);
    }

    private List<DisasmLine> RenderFinal(
        byte[] bytes, int fileOff, ulong startIp,
        List<Instruction> raws, HashSet<ulong> functionStarts,
        MasmFormatter formatter, string? startLabel,
        List<DisasmLine> lines)
    {
        if (raws.Count == 0) return lines;
        ulong firstIp = raws[0].IP;
        ulong lastIp  = raws[^1].IP;

        var localLabels = new Dictionary<ulong, string>();
        foreach (var instr in raws)
        {
            if (!IsLocalBranch(instr)) continue;
            ulong target = instr.NearBranch64;
            if (target < firstIp || target > lastIp) continue;
            if (_symbolMap.ContainsKey(target)) continue;
            if (!localLabels.ContainsKey(target))
                localLabels[target] = $"loc_{target:X}";
        }

        var xrefs = AppState.Instance.Analysis?.Xrefs;
        int padTo = (_bitness == 64 ? 24 : 18);
        bool first = true;

        foreach (var instr in raws)
        {
            ulong ip = instr.IP;

            if (functionStarts.Contains(ip))
            {
                string headerName = first && !string.IsNullOrEmpty(startLabel)
                    ? startLabel
                    : (_symbolMap.TryGetValue(ip, out var sn) ? sn : $"sub_{ip:X}");
                if (!first) lines.Add(DisasmLine.Plain(""));
                lines.Add(DisasmLine.Plain($"; ============= function: {headerName} ============="));

                if (xrefs is not null && xrefs.TryGetValue(ip, out var sources) && sources.Count > 0)
                {
                    var line = new DisasmLine();
                    line.Add("; called from: ", null);
                    for (int i = 0; i < Math.Min(sources.Count, 8); i++)
                    {
                        if (i > 0) line.Add(", ", null);
                        line.AddHyperlink($"0x{sources[i]:X}", (uint)(sources[i] - _imageBase));
                    }
                    if (sources.Count > 8) line.Add($"  (+{sources.Count - 8} more)", null);
                    lines.Add(line);
                }

                lines.Add(DisasmLine.Plain(""));
                first = false;
            }

            if (localLabels.TryGetValue(ip, out var lblHere))
            {
                var line = new DisasmLine();
                line.Add(lblHere + ":", FormatterTextKind.LabelAddress);
                lines.Add(line);
            }

            var dl = new DisasmLine();
            dl.Add($"  {ip:X16}  ", FormatterTextKind.LabelAddress);

            int instrLen = instr.Length;
            var hex = new StringBuilder(instrLen * 3);
            for (int i = 0; i < instrLen; i++)
            {
                hex.Append(bytes[fileOff + (int)(ip - startIp) + i].ToString("X2"));
                if (i + 1 < instrLen) hex.Append(' ');
            }
            dl.Add(hex.ToString().PadRight(padTo) + "  ", FormatterTextKind.Data);

            if (instr.IsInvalid)
            {
                dl.Add("(invalid)", null);
                lines.Add(dl);
                continue;
            }

            var sink = new SegmentCollector();
            formatter.Format(instr, sink);
            foreach (var (t, k) in sink.Segments) dl.Add(t, k);

            if (IsLocalBranch(instr) || instr.IsCallNear)
            {
                ulong target = instr.NearBranch64;
                if (_symbolMap.TryGetValue(target, out var sym))
                {
                    dl.Add("   ; -> ", null);
                    dl.AddHyperlink(sym, (uint)(target - _imageBase));
                }
                else if (localLabels.TryGetValue(target, out var lbl))
                {
                    dl.Add("   ; -> ", null);
                    dl.AddHyperlink(lbl, (uint)(target - _imageBase));
                }
            }

            lines.Add(dl);

            if (instr.FlowControl == FlowControl.Return)
                lines.Add(DisasmLine.Plain("  ; --- end of function ---"));
        }
        return lines;
    }

    private static bool IsLocalBranch(Instruction instr) =>
        instr.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
        && (instr.IsJmpNear || instr.IsJmpShort || instr.IsJccNear || instr.IsJccShort);

    private void RenderLines(List<DisasmLine> lines)
    {
        AsmBox.Blocks.Clear();
        foreach (var line in lines)
        {
            var p = new Paragraph();
            foreach (var seg in line.Segments)
            {
                if (seg.LinkRva.HasValue)
                {
                    var hl = new Hyperlink();
                    uint target = seg.LinkRva.Value;
                    hl.Click += (s, e) => _ = NavigateAsync(target, pushHistory: true);
                    hl.Inlines.Add(new Run { Text = seg.Text });
                    p.Inlines.Add(hl);
                }
                else
                {
                    p.Inlines.Add(new Run { Text = seg.Text, Foreground = seg.Kind is { } k ? BrushForKind(k) : DefaultBrush() });
                }
            }
            AsmBox.Blocks.Add(p);
        }
        StatusMessage.Visibility = Visibility.Collapsed;
        AsmScroller.Visibility = Visibility.Visible;
    }

    private static SolidColorBrush? _brushDefault;
    private static SolidColorBrush BrushForKind(FormatterTextKind kind)
    {
        return kind switch
        {
            FormatterTextKind.Mnemonic       => Solid(Color.FromArgb(255, 245, 158, 11)),
            FormatterTextKind.Prefix         => Solid(Color.FromArgb(255, 217, 119, 6)),
            FormatterTextKind.Register       => Solid(Color.FromArgb(255, 96,  165, 250)),
            FormatterTextKind.Number         => Solid(Color.FromArgb(255, 134, 239, 172)),
            FormatterTextKind.LabelAddress   => Solid(Color.FromArgb(255, 148, 163, 184)),
            FormatterTextKind.FunctionAddress=> Solid(Color.FromArgb(255, 56,  189, 248)),
            FormatterTextKind.Data           => Solid(Color.FromArgb(255, 113, 113, 122)),
            FormatterTextKind.Decorator      => Solid(Color.FromArgb(255, 196, 181, 253)),
            FormatterTextKind.SelectorValue  => Solid(Color.FromArgb(255, 196, 181, 253)),
            FormatterTextKind.Keyword        => Solid(Color.FromArgb(255, 165, 243, 252)),
            FormatterTextKind.Operator       => Solid(Color.FromArgb(255, 161, 161, 170)),
            FormatterTextKind.Punctuation    => Solid(Color.FromArgb(255, 161, 161, 170)),
            _                                => DefaultBrush(),
        };
    }

    private static SolidColorBrush Solid(Color c) => new SolidColorBrush(c);
    private static SolidColorBrush DefaultBrush() => _brushDefault ??= new SolidColorBrush(Color.FromArgb(255, 228, 228, 231));

    private void ShowStatus(string message, InfoBarSeverity severity)
    {
        StatusBar.Severity = severity;
        StatusBar.Message = message;
        StatusBar.IsOpen = true;
    }

    private void ShowStatusMessage(string message)
    {
        StatusMessage.Text = message;
        StatusMessage.Visibility = Visibility.Visible;
        AsmScroller.Visibility = Visibility.Collapsed;
    }

    private sealed record DisasmStart(string Label, uint Rva);
    private sealed record NavState(uint Rva, int Count, DisasmMode Mode);

    private sealed class DisasmLine
    {
        public List<Segment> Segments { get; } = new();
        public void Add(string text, FormatterTextKind? kind) => Segments.Add(new Segment(text, kind, null));
        public void AddHyperlink(string text, uint rva) => Segments.Add(new Segment(text, null, rva));
        public static DisasmLine Plain(string text)
        {
            var l = new DisasmLine();
            l.Add(text, null);
            return l;
        }
        public sealed record Segment(string Text, FormatterTextKind? Kind, uint? LinkRva);
    }

    private sealed class SegmentCollector : FormatterOutput
    {
        public readonly List<(string Text, FormatterTextKind Kind)> Segments = new();
        public override void Write(string text, FormatterTextKind kind) => Segments.Add((text, kind));
    }
}
