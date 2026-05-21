using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using BinaryExplorer.Pages;
using BinaryExplorer.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.Graphics;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using Windows.UI;

namespace BinaryExplorer;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        AppWindow.SetIcon("Assets/AppIcon.ico");

        NavFrame.Navigate(typeof(OverviewPage));

        // Screenshot mode: if a request file exists in the user profile, the app
        // loads a sample binary, walks the curated pages capturing each to a PNG,
        // writes a .done file, then exits. A file marker (not an env var / CLI
        // arg) is used because packaged-app activation does not inherit either.
        string requestFile = ScreenshotRequestPath();
        if (File.Exists(requestFile))
            _ = RunScreenshotsAsync(requestFile);
    }

    private static string ScreenshotRequestPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".binexp-screenshots.json");

    // Pages captured against the primary (native PE) sample, in nav order.
    private static readonly (string Tag, string Slug)[] PrimaryPages =
    {
        ("overview",     "overview"),
        ("language",     "language"),
        ("versioninfo",  "version-info"),
        ("signature",    "signature"),
        ("hashes",       "hashes"),
        ("richheader",   "rich-header"),
        ("debug",        "debug-info"),
        ("etw",          "etw"),
        ("dependencies", "dependencies"),
        ("capabilities", "capabilities"),
        ("interfaces",   "com-rpc"),
        ("strings",      "strings"),
        ("tls",          "tls-callbacks"),
        ("disassembly",  "disassembly"),
        ("pe",           "pe"),
        ("resources",    "resources"),
        ("packing",      "packing"),
        ("embedded",     "embedded-files"),
        ("hex",          "hex-view"),
        ("motw",         "mark-of-the-web"),
        ("virustotal",   "virustotal"),
        ("yara",         "yara"),
        ("tools",        "tools"),
    };

    private static string? FindSampleMsi()
    {
        try
        {
            const string dir = @"C:\Windows\Installer";
            if (Directory.Exists(dir))
                return Directory.EnumerateFiles(dir, "*.msi")
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.Length)
                    .Select(f => f.FullName)
                    .FirstOrDefault();
        }
        catch { /* ignore */ }
        return null;
    }

    private async Task RunScreenshotsAsync(string requestFile)
    {
        string outputDir = "";
        string doneFile = Path.ChangeExtension(requestFile, ".done");
        try
        {
            string? sample, msiSample;
            using (var doc = JsonDocument.Parse(File.ReadAllText(requestFile)))
            {
                outputDir = doc.RootElement.GetProperty("outputDir").GetString() ?? "";
                sample = doc.RootElement.TryGetProperty("sample", out var s) ? s.GetString() : null;
                msiSample = doc.RootElement.TryGetProperty("msiSample", out var m) ? m.GetString() : null;
            }
            File.Delete(requestFile);   // consume the request
            Directory.CreateDirectory(outputDir);

            // Fixed size + forced dark theme + solid background, so captures are
            // consistent and the Mica backdrop doesn't bleed transparency into PNGs.
            AppWindow.Resize(new SizeInt32(1400, 900));
            if (Content is Grid root)
            {
                root.RequestedTheme = ElementTheme.Dark;
                root.Background = new SolidColorBrush(Color.FromArgb(0xFF, 0x20, 0x20, 0x20));
            }
            await Task.Delay(1000);

            int n = 1;
            async Task ShotAsync(string slug)
            {
                await Task.Delay(900);
                await CaptureAsync(Path.Combine(outputDir, $"{n:D2}-{slug}.png"));
                n++;
            }
            void Nav(string tag)
            {
                var item = NavLeaves().FirstOrDefault(x => (string?)x.Tag == tag);
                if (item is not null) NavView.SelectedItem = item;
            }

            // Primary native sample — covers most pages.
            sample ??= @"C:\Windows\System32\notepad.exe";
            if (File.Exists(sample))
                await BinaryLoader.LoadAsync(sample);
            await Task.Delay(500);

            // Expand every nav group so the sidebar reads as the full feature list.
            foreach (var nvi in AllNavItems())
                if (nvi.MenuItems.Count > 0) nvi.IsExpanded = true;

            foreach (var (tag, slug) in PrimaryPages)
            {
                Nav(tag);
                if (tag == "disassembly")
                {
                    await Task.Delay(1600);   // wait for function analysis
                    if (NavFrame.Content is DisassemblyPage dp) await dp.ShowEntryAsync();
                }
                await ShotAsync(slug);
            }

            // Compare — needs a second file in the right-hand slot.
            try
            {
                await CompareState.Instance.LoadAsync(@"C:\Windows\System32\kernel32.dll");
                await Task.Delay(400);
            }
            catch { /* leave the compare page in its empty state */ }
            Nav("compare");
            await ShotAsync("compare");

            // Decompile — needs a managed assembly; use the app's own .NET module.
            string dotnetSample = Path.Combine(AppContext.BaseDirectory, "BinaryExplorer.dll");
            if (File.Exists(dotnetSample))
            {
                await BinaryLoader.LoadAsync(dotnetSample);
                await Task.Delay(500);
            }
            Nav("decompile");
            await Task.Delay(1500);   // wait for the decompiler to load + build the type tree
            if (NavFrame.Content is DecompilePage dcp) await dcp.ShowSampleAsync();
            await ShotAsync("decompile");

            // MSI — needs an installer database (the script passes our own built MSI).
            msiSample ??= FindSampleMsi();
            if (msiSample is not null && File.Exists(msiSample))
            {
                await BinaryLoader.LoadAsync(msiSample);
                await Task.Delay(600);
            }
            Nav("msi");
            await ShotAsync("msi");

            // Settings + the About card (scrolled into view).
            NavView.SelectedItem = NavView.SettingsItem;
            await ShotAsync("settings");
            if (NavFrame.Content is Page settingsPage
                && settingsPage.Content is ScrollViewer sv)
            {
                sv.UpdateLayout();
                sv.ChangeView(null, sv.ScrollableHeight, null, true);
                await ShotAsync("about");
            }

            File.WriteAllText(doneFile, "ok");
        }
        catch (Exception ex)
        {
            try { File.WriteAllText(doneFile, "ERROR: " + ex); } catch { /* best effort */ }
            try
            {
                if (!string.IsNullOrEmpty(outputDir))
                    File.WriteAllText(Path.Combine(outputDir, "error.txt"), ex.ToString());
            }
            catch { /* best effort */ }
        }
        finally
        {
            Close();
        }
    }

    private async Task CaptureAsync(string path)
    {
        var rtb = new RenderTargetBitmap();
        await rtb.RenderAsync((UIElement)Content);
        var buffer = await rtb.GetPixelsAsync();
        var pixels = new byte[buffer.Length];
        using (var dr = DataReader.FromBuffer(buffer)) dr.ReadBytes(pixels);

        var stream = new InMemoryRandomAccessStream();
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetPixelData(
            BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
            (uint)rtb.PixelWidth, (uint)rtb.PixelHeight, 96, 96, pixels);
        await encoder.FlushAsync();

        stream.Seek(0);
        var png = new byte[stream.Size];
        using (var dr = new DataReader(stream))
        {
            await dr.LoadAsync((uint)stream.Size);
            dr.ReadBytes(png);
        }
        stream.Dispose();
        await File.WriteAllBytesAsync(path, png);
    }

    private void TitleBar_PaneToggleRequested(TitleBar sender, object args)
    {
        NavView.IsPaneOpen = !NavView.IsPaneOpen;
    }

    private void TitleBar_BackRequested(TitleBar sender, object args)
    {
        NavFrame.GoBack();
    }

    private IEnumerable<NavigationViewItem> AllNavItems()
    {
        return Recurse(NavView.MenuItems);

        static IEnumerable<NavigationViewItem> Recurse(IList<object> items)
        {
            foreach (var raw in items)
            {
                if (raw is NavigationViewItem nvi)
                {
                    yield return nvi;
                    foreach (var sub in Recurse(nvi.MenuItems))
                        yield return sub;
                }
            }
        }
    }

    private IEnumerable<NavigationViewItem> NavLeaves()
        => AllNavItems().Where(n => n.Tag is string);

    private void NavSearch_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        var query = sender.Text?.Trim() ?? "";
        ApplyFilter(NavView.MenuItems, query);

        if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput && query.Length > 0)
        {
            sender.ItemsSource = NavLeaves()
                .Where(n => (n.Content as string ?? "").Contains(query, System.StringComparison.OrdinalIgnoreCase))
                .Select(n => (string)n.Content)
                .ToList();
        }
        else
        {
            sender.ItemsSource = null;
        }
    }

    private static bool ApplyFilter(IList<object> items, string query)
    {
        bool anyVisible = false;
        foreach (var raw in items)
        {
            if (raw is not NavigationViewItem nvi) continue;
            string label = nvi.Content as string ?? "";
            bool selfMatch = query.Length == 0 || label.Contains(query, System.StringComparison.OrdinalIgnoreCase);
            bool childVisible = ApplyFilter(nvi.MenuItems, query);
            bool visible = selfMatch || childVisible;
            nvi.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            if (query.Length > 0 && childVisible) nvi.IsExpanded = true;
            if (visible) anyVisible = true;
        }
        return anyVisible;
    }

    private void NavSearch_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
    {
        sender.Text = args.SelectedItem as string ?? sender.Text;
    }

    private void NavSearch_QuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args)
    {
        string target = (args.ChosenSuggestion as string) ?? sender.Text?.Trim() ?? "";
        var first = NavLeaves().FirstOrDefault(n =>
        {
            string label = (n.Content as string ?? "");
            return target.Length > 0 && label.Equals(target, System.StringComparison.OrdinalIgnoreCase);
        }) ?? NavLeaves().FirstOrDefault(n =>
        {
            string label = (n.Content as string ?? "");
            return target.Length > 0 && label.Contains(target, System.StringComparison.OrdinalIgnoreCase);
        });
        if (first is not null) NavView.SelectedItem = first;
        sender.Text = "";
        sender.ItemsSource = null;
        ApplyFilter(NavView.MenuItems, "");
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            NavFrame.Navigate(typeof(SettingsPage));
            return;
        }
        if (args.SelectedItem is NavigationViewItem item)
        {
            Type? target = item.Tag switch
            {
                "overview"     => typeof(OverviewPage),
                "compare"      => typeof(ComparePage),
                "language"     => typeof(LanguagePage),
                "versioninfo"  => typeof(VersionInfoPage),
                "signature"    => typeof(SignaturePage),
                "hashes"       => typeof(HashesPage),
                "richheader"   => typeof(RichHeaderPage),
                "debug"        => typeof(DebugPage),
                "etw"          => typeof(EtwPage),
                "dependencies" => typeof(DependenciesPage),
                "capabilities" => typeof(CapabilitiesPage),
                "interfaces"   => typeof(InterfacesPage),
                "strings"      => typeof(StringsPage),
                "tls"          => typeof(TlsPage),
                "decompile"    => typeof(DecompilePage),
                "disassembly"  => typeof(DisassemblyPage),
                "pe"           => typeof(PePage),
                "resources"    => typeof(ResourcesPage),
                "packing"      => typeof(PackingPage),
                "embedded"     => typeof(EmbeddedPage),
                "msi"          => typeof(MsiPage),
                "hex"          => typeof(HexPage),
                "motw"         => typeof(MotwPage),
                "virustotal"   => typeof(VirusTotalPage),
                "yara"         => typeof(YaraPage),
                "tools"        => typeof(ToolsPage),
                _ => null,
            };
            if (target is not null) NavFrame.Navigate(target);
        }
    }
}
