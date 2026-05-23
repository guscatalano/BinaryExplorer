using System.ComponentModel;
using System.IO;
using BinaryExplorer.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace BinaryExplorer.Pages;

public sealed partial class OverviewPage : Page
{
    public OverviewPage()
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
        PathText.Text = AppState.Instance.DisplayName;
        LanguageHeadline.Text = AppState.Instance.GetResult("Language")?.Headline ?? "—";
        SignatureHeadline.Text = AppState.Instance.GetResult("Signature")?.Headline ?? "—";
        EtwHeadline.Text = AppState.Instance.GetResult("ETW")?.Headline ?? "—";
        PeHeadline.Text = AppState.Instance.GetResult("PE")?.Headline ?? "—";
        ExportButton.IsEnabled = AppState.Instance.IsLoaded;

        var ctx = AppState.Instance.Binary;
        MsiInfoBar.IsOpen = ctx is not null
            && BinaryExplorer.Services.Mcp.MsiQuery.IsCompoundFileBinary(ctx.Bytes);
    }

    private void Page_DragOver(object sender, DragEventArgs e)
    {
        if (e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            e.AcceptedOperation = DataPackageOperation.Copy;
            e.DragUIOverride.Caption = "Inspect this binary";
            e.DragUIOverride.IsCaptionVisible = true;
            e.DragUIOverride.IsContentVisible = true;
        }
    }

    private async void Page_Drop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        var items = await e.DataView.GetStorageItemsAsync();
        var file = items.OfType<StorageFile>().FirstOrDefault();
        if (file is null) return;
        await LoadFileAsync(file.Path);
    }

    private async Task LoadFileAsync(string path)
    {
        ErrorBar.IsOpen = false;
        LoadingRing.IsActive = true;
        OpenButton.IsEnabled = false;
        try
        {
            await BinaryLoader.LoadAsync(path);
        }
        catch (Exception ex)
        {
            ErrorBar.Message = ex.Message;
            ErrorBar.IsOpen = true;
        }
        finally
        {
            LoadingRing.IsActive = false;
            OpenButton.IsEnabled = true;
        }
    }

    private async void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (!AppState.Instance.IsLoaded) return;

        var picker = new FileSavePicker();
        picker.SuggestedFileName = Path.GetFileNameWithoutExtension(AppState.Instance.Binary!.Path) + "-report";
        picker.FileTypeChoices.Add("Markdown", new List<string> { ".md" });
        picker.FileTypeChoices.Add("JSON",     new List<string> { ".json" });

        var hwnd = App.MainWindow is null ? IntPtr.Zero : WindowNative.GetWindowHandle(App.MainWindow);
        InitializeWithWindow.Initialize(picker, hwnd);

        var file = await picker.PickSaveFileAsync();
        if (file is null) return;

        try
        {
            string content;
            if (file.FileType.Equals(".json", StringComparison.OrdinalIgnoreCase))
            {
                content = System.Text.Json.JsonSerializer.Serialize(
                    new
                    {
                        path = AppState.Instance.Binary!.Path,
                        sizeBytes = AppState.Instance.Binary.Bytes.LongLength,
                        generatedUtc = DateTimeOffset.UtcNow,
                        results = AppState.Instance.Results.Values.Select(r => new
                        {
                            inspector = r.InspectorName,
                            headline = r.Headline,
                            error = r.Error,
                            findings = r.Findings.Select(f => new { f.Title, f.Value, f.Details, severity = f.Severity.ToString() }),
                        }),
                    },
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            }
            else
            {
                content = ReportExporter.BuildMarkdown();
            }
            await Windows.Storage.FileIO.WriteTextAsync(file, content);
            ErrorBar.Severity = InfoBarSeverity.Success;
            ErrorBar.Title = "Saved";
            ErrorBar.Message = $"Report written to {file.Path}";
            ErrorBar.IsOpen = true;
        }
        catch (Exception ex)
        {
            ErrorBar.Severity = InfoBarSeverity.Error;
            ErrorBar.Title = "Export failed";
            ErrorBar.Message = ex.Message;
            ErrorBar.IsOpen = true;
        }
    }

    private async void OpenButton_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".exe");
        picker.FileTypeFilter.Add(".dll");
        picker.FileTypeFilter.Add(".sys");
        picker.FileTypeFilter.Add(".winmd");
        picker.FileTypeFilter.Add("*");

        var hwnd = App.MainWindow is null ? IntPtr.Zero : WindowNative.GetWindowHandle(App.MainWindow);
        InitializeWithWindow.Initialize(picker, hwnd);

        var file = await picker.PickSingleFileAsync();
        if (file is null) return;

        await LoadFileAsync(file.Path);
    }
}
