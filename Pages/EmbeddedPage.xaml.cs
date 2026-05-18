using System.ComponentModel;
using BinaryExplorer.Core;
using BinaryExplorer.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace BinaryExplorer.Pages;

public sealed partial class EmbeddedPage : Page
{
    private List<EmbeddedHitGroup> _groups = new();

    public EmbeddedPage()
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
        if (!AppState.Instance.IsLoaded)
        {
            HeadlineText.Text = "No file loaded. Open one from the Overview page.";
            SummaryText.Text = "";
            _groups.Clear();
            GroupsControl.ItemsSource = null;
            return;
        }
        var result = AppState.Instance.GetResult("Embedded");
        if (result is null)
        {
            HeadlineText.Text = "Scanning...";
            SummaryText.Text = "";
            GroupsControl.ItemsSource = null;
            return;
        }
        HeadlineText.Text = result.Headline ?? "";
        var hits = (result.Payload as IEnumerable<EmbeddedHit>)?.ToList() ?? new List<EmbeddedHit>();

        _groups = hits
            .GroupBy(h => h.Type, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .Select((g, i) => new EmbeddedHitGroup(g.Key,
                g.OrderBy(h => h.Offset).ToList(),
                isExpanded: i == 0))   // expand the largest group by default
            .ToList();
        GroupsControl.ItemsSource = _groups;

        // Inline summary chip row.
        SummaryText.Text = string.Join("    ",
            _groups.Select(g => $"{g.Type}: {g.Count}"));
    }

    private void ExpandAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var g in _groups) g.IsExpanded = true;
    }

    private void CollapseAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var g in _groups) g.IsExpanded = false;
    }

    private async void Rescan_Click(object sender, RoutedEventArgs e)
    {
        if (!AppState.Instance.IsLoaded) return;
        ShowStatus("Rescanning embedded files...", InfoBarSeverity.Informational);
        try
        {
            await BinaryLoader.RescanAsync("Embedded");
            ShowStatus("Rescan complete.", InfoBarSeverity.Success);
        }
        catch (Exception ex)
        {
            ShowStatus($"Rescan failed: {ex.Message}", InfoBarSeverity.Error);
        }
    }

    private async void ExtractButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not EmbeddedHit hit) return;
        var ctx = AppState.Instance.Binary;
        if (ctx is null) return;
        try
        {
            string path = await EmbeddedExtractor.ExtractAsync(ctx, hit);
            EmbeddedExtractor.RevealInExplorer(path);
            ShowStatus($"Extracted to {path}", InfoBarSeverity.Success);
        }
        catch (Exception ex)
        {
            ShowStatus($"Extract failed: {ex.Message}", InfoBarSeverity.Error);
        }
    }

    private async void OpenButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not EmbeddedHit hit) return;
        var ctx = AppState.Instance.Binary;
        if (ctx is null) return;

        if (!hit.SizeIsKnown)
        {
            var confirm = new ContentDialog
            {
                XamlRoot = this.XamlRoot,
                Title = "Size unknown",
                Content = $"BinaryExplorer couldn't determine the exact size of this {hit.Type} blob. Extracting up to 32MB and opening with the default handler. Continue?",
                PrimaryButtonText = "Open anyway",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Close,
            };
            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;
        }

        try
        {
            string path = await EmbeddedExtractor.ExtractAsync(ctx, hit);
            EmbeddedExtractor.OpenWithDefaultHandler(path);
            ShowStatus($"Opened {path}", InfoBarSeverity.Success);
        }
        catch (Exception ex)
        {
            ShowStatus($"Open failed: {ex.Message}", InfoBarSeverity.Error);
        }
    }

    private void ShowStatus(string message, InfoBarSeverity severity)
    {
        StatusBar.Severity = severity;
        StatusBar.Message = message;
        StatusBar.IsOpen = true;
    }
}
