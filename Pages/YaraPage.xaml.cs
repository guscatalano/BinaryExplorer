using BinaryExplorer.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace BinaryExplorer.Pages;

public sealed partial class YaraPage : Page
{
    public YaraPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        YaraPathBox.Text = Settings.YaraExePath;
        if (string.IsNullOrEmpty(Settings.YaraRulesPath))
        {
            var bundled = System.IO.Path.Combine(AppContext.BaseDirectory, "tools", "yara", "default.yar");
            if (System.IO.File.Exists(bundled))
                Settings.YaraRulesPath = bundled;
        }
        RulesPathBox.Text = Settings.YaraRulesPath ?? "";
    }

    private async void BrowseYara_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".exe");
        picker.FileTypeFilter.Add("*");
        InitForWindow(picker);
        var file = await picker.PickSingleFileAsync();
        if (file is not null)
        {
            YaraPathBox.Text = file.Path;
            Settings.YaraExePath = file.Path;
        }
    }

    private async void BrowseRulesFile_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".yar");
        picker.FileTypeFilter.Add(".yara");
        picker.FileTypeFilter.Add("*");
        InitForWindow(picker);
        var file = await picker.PickSingleFileAsync();
        if (file is not null)
        {
            RulesPathBox.Text = file.Path;
            Settings.YaraRulesPath = file.Path;
        }
    }

    private async void BrowseRulesFolder_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FolderPicker();
        picker.FileTypeFilter.Add("*");
        InitForWindow(picker);
        var folder = await picker.PickSingleFolderAsync();
        if (folder is not null)
        {
            RulesPathBox.Text = folder.Path;
            Settings.YaraRulesPath = folder.Path;
        }
    }

    private void InitForWindow(object picker)
    {
        var hwnd = App.MainWindow is null ? IntPtr.Zero : WindowNative.GetWindowHandle(App.MainWindow);
        InitializeWithWindow.Initialize(picker, hwnd);
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        ErrorBar.IsOpen = false;
        MatchesList.ItemsSource = null;

        var ctx = AppState.Instance.Binary;
        if (ctx is null)
        {
            ShowError("Load a binary on the Overview page first.");
            return;
        }
        string yaraExe = YaraPathBox.Text?.Trim() ?? "yara.exe";
        string rules = RulesPathBox.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(rules))
        {
            ShowError("Pick a YARA rules file or directory.");
            return;
        }
        Settings.YaraExePath = yaraExe;
        Settings.YaraRulesPath = rules;

        ScanRing.IsActive = true;
        StatusText.Text = "Scanning...";
        try
        {
            var result = await YaraScanner.ScanAsync(yaraExe, rules, ctx.Path);
            if (!string.IsNullOrEmpty(result.Error))
            {
                ShowError(result.Error);
                StatusText.Text = "";
                return;
            }
            MatchesList.ItemsSource = result.Matches;
            StatusText.Text = $"{result.Matches.Count} rule match(es) — {result.Duration.TotalMilliseconds:F0} ms";
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
        finally
        {
            ScanRing.IsActive = false;
        }
    }

    private async void Download_Click(object sender, RoutedEventArgs e)
    {
        ErrorBar.IsOpen = false;
        ScanRing.IsActive = true;
        StatusText.Text = "Downloading YARA...";
        try
        {
            var progress = new Progress<string>(msg =>
                DispatcherQueue.TryEnqueue(() => StatusText.Text = msg));
            string exe = await YaraDownloader.DownloadLatestAsync(progress);
            YaraPathBox.Text = exe;
            Settings.YaraExePath = exe;
            StatusText.Text = $"Installed: {exe}";
        }
        catch (Exception ex)
        {
            ShowError($"Download failed: {ex.Message}");
            StatusText.Text = "";
        }
        finally
        {
            ScanRing.IsActive = false;
        }
    }

    private void ShowError(string message)
    {
        ErrorBar.Message = message;
        ErrorBar.IsOpen = true;
    }
}
