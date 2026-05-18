using System.ComponentModel;
using BinaryExplorer.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace BinaryExplorer.Pages;

public sealed partial class HexPage : Page
{
    private int _skip;
    private int _length = 4096;

    public HexPage()
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
            Hex.Bytes = null;
            return;
        }
        Hex.Bytes = ctx.Bytes;
        Hex.BaseOffset = 0;
        Hex.MaxBytes = _length;
        Hex.Skip = _skip;
        OffsetInput.Text = "0x" + _skip.ToString("X");
        HeadlineText.Text = $"{System.IO.Path.GetFileName(ctx.Path)} — {ctx.Bytes.LongLength:N0} bytes total · viewing 0x{_skip:X}..0x{(long)_skip + _length:X}";
    }

    private void Go_Click(object sender, RoutedEventArgs e)
    {
        if (TryParseOffset(OffsetInput.Text, out int off))
            _skip = Math.Max(0, off);
        _length = Math.Clamp((int)LengthInput.Value, 16, 262144);
        Refresh();
    }

    private void PageBack_Click(object sender, RoutedEventArgs e)
    {
        _skip = Math.Max(0, _skip - _length);
        Refresh();
    }

    private void PageForward_Click(object sender, RoutedEventArgs e)
    {
        var ctx = AppState.Instance.Binary;
        if (ctx is null) return;
        _skip = Math.Min((int)(ctx.Bytes.LongLength - 1), _skip + _length);
        Refresh();
    }

    private static bool TryParseOffset(string? text, out int value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return int.TryParse(text.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out value);
        if (text.StartsWith("0n", StringComparison.OrdinalIgnoreCase))
            return int.TryParse(text.AsSpan(2), out value);
        return int.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out value);
    }
}
