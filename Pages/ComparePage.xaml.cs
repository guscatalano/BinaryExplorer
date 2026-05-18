using System.ComponentModel;
using BinaryExplorer.Core;
using BinaryExplorer.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace BinaryExplorer.Pages;

public sealed partial class ComparePage : Page
{
    public ComparePage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged += OnAnyChange;
        CompareState.Instance.PropertyChanged += OnAnyChange;
        Refresh();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged -= OnAnyChange;
        CompareState.Instance.PropertyChanged -= OnAnyChange;
    }

    private void OnAnyChange(object? sender, PropertyChangedEventArgs e)
    {
        DispatcherQueue.TryEnqueue(Refresh);
    }

    private void Refresh()
    {
        LeftPathText.Text  = AppState.Instance.IsLoaded     ? AppState.Instance.DisplayName     : "No left file";
        RightPathText.Text = CompareState.Instance.IsLoaded ? CompareState.Instance.DisplayName : "No right file";

        // Build the inspector list from whatever results are available.
        var leftNames  = AppState.Instance.Results.Keys;
        var rightNames = CompareState.Instance.Results.Keys;
        var union = leftNames.Union(rightNames).OrderBy(s => s, StringComparer.Ordinal).ToList();

        if (union.Count == 0)
        {
            InspectorCombo.ItemsSource = null;
            RowList.ItemsSource = null;
            SummaryText.Text = "Load both files to compare.";
            return;
        }

        string? previously = InspectorCombo.SelectedItem as string;
        InspectorCombo.ItemsSource = union;
        if (previously is not null && union.Contains(previously))
            InspectorCombo.SelectedItem = previously;
        else
            InspectorCombo.SelectedIndex = 0;
    }

    private void InspectorCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (InspectorCombo.SelectedItem is not string name)
        {
            RowList.ItemsSource = null;
            SummaryText.Text = "";
            return;
        }

        var left  = AppState.Instance.GetResult(name);
        var right = CompareState.Instance.GetResult(name);

        var lFindings = left?.Findings  ?? Array.Empty<Finding>();
        var rFindings = right?.Findings ?? Array.Empty<Finding>();

        var rows = new List<ComparisonRow>();
        var usedRight = new HashSet<int>();
        for (int li = 0; li < lFindings.Count; li++)
        {
            var l = lFindings[li];
            int matchIdx = -1;
            for (int ri = 0; ri < rFindings.Count; ri++)
            {
                if (usedRight.Contains(ri)) continue;
                if (string.Equals(rFindings[ri].Title, l.Title, StringComparison.Ordinal))
                {
                    matchIdx = ri;
                    break;
                }
            }
            if (matchIdx >= 0)
            {
                rows.Add(new ComparisonRow(l.Title, l.Value, rFindings[matchIdx].Value));
                usedRight.Add(matchIdx);
            }
            else
            {
                rows.Add(new ComparisonRow(l.Title, l.Value, null));
            }
        }
        for (int ri = 0; ri < rFindings.Count; ri++)
        {
            if (usedRight.Contains(ri)) continue;
            rows.Add(new ComparisonRow(rFindings[ri].Title, null, rFindings[ri].Value));
        }

        RowList.ItemsSource = rows;

        int eq = rows.Count(r => r.Equal);
        int diff = rows.Count(r => r.Different);
        int only = rows.Count(r => r.OnlyLeft || r.OnlyRight);
        string lH = left?.Headline ?? "—";
        string rH = right?.Headline ?? "—";
        SummaryText.Text = $"  ·  L: {lH}  ·  R: {rH}  ·  = {eq}    ≠ {diff}    one-side {only}";
    }

    private async void OpenLeft_Click(object sender, RoutedEventArgs e)
    {
        var file = await PickFileAsync();
        if (file is null) return;
        LeftRing.IsActive = true;
        LeftOpenButton.IsEnabled = false;
        try { await BinaryLoader.LoadAsync(file.Path); }
        finally { LeftRing.IsActive = false; LeftOpenButton.IsEnabled = true; }
    }

    private async void OpenRight_Click(object sender, RoutedEventArgs e)
    {
        var file = await PickFileAsync();
        if (file is null) return;
        RightRing.IsActive = true;
        RightOpenButton.IsEnabled = false;
        try { await CompareState.Instance.LoadAsync(file.Path); }
        finally { RightRing.IsActive = false; RightOpenButton.IsEnabled = true; }
    }

    private async Task<Windows.Storage.StorageFile?> PickFileAsync()
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".exe");
        picker.FileTypeFilter.Add(".dll");
        picker.FileTypeFilter.Add(".sys");
        picker.FileTypeFilter.Add(".winmd");
        picker.FileTypeFilter.Add("*");
        var hwnd = App.MainWindow is null ? IntPtr.Zero : WindowNative.GetWindowHandle(App.MainWindow);
        InitializeWithWindow.Initialize(picker, hwnd);
        return await picker.PickSingleFileAsync();
    }
}
