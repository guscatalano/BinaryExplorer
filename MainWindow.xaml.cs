using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using BinaryExplorer.Pages;
using System.Collections.Generic;
using System.Linq;

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
                _ => null,
            };
            if (target is not null) NavFrame.Navigate(target);
        }
    }
}
