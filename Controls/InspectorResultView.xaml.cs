using System.ComponentModel;
using BinaryExplorer.Core;
using BinaryExplorer.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace BinaryExplorer.Controls;

public sealed partial class InspectorResultView : UserControl
{
    private IReadOnlyList<Finding>? _originalFindings;

    public InspectorResultView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;

        var openSearch = new KeyboardAccelerator { Key = VirtualKey.F, Modifiers = VirtualKeyModifiers.Control };
        openSearch.Invoked += (s, e) => { OpenSearch(); e.Handled = true; };
        KeyboardAccelerators.Add(openSearch);
    }

    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(InspectorResultView),
            new PropertyMetadata("", OnTitleChanged));

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((InspectorResultView)d).TitleText.Text = (string)e.NewValue;
    }

    public static readonly DependencyProperty InspectorNameProperty =
        DependencyProperty.Register(nameof(InspectorName), typeof(string), typeof(InspectorResultView),
            new PropertyMetadata("", (d, _) => ((InspectorResultView)d).Refresh()));

    public string InspectorName
    {
        get => (string)GetValue(InspectorNameProperty);
        set => SetValue(InspectorNameProperty, value);
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        AppState.Instance.PropertyChanged += OnStateChanged;
        Refresh();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
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
            HeadlineText.Text = "";
            EmptyText.Visibility = Visibility.Visible;
            ErrorBar.IsOpen = false;
            _originalFindings = null;
            List.Findings = null;
            CloseSearch();
            return;
        }
        EmptyText.Visibility = Visibility.Collapsed;

        var result = AppState.Instance.GetResult(InspectorName);
        if (result is null)
        {
            HeadlineText.Text = "Running...";
            _originalFindings = null;
            List.Findings = null;
            ErrorBar.IsOpen = false;
            return;
        }
        HeadlineText.Text = result.Headline ?? "";
        _originalFindings = result.Findings;

        if (!string.IsNullOrEmpty(SearchBox.Text))
            ApplySearch(SearchBox.Text);
        else
            List.Findings = _originalFindings;

        if (!string.IsNullOrEmpty(result.Error))
        {
            ErrorBar.Message = result.Error;
            ErrorBar.IsOpen = true;
        }
        else
        {
            ErrorBar.IsOpen = false;
        }
    }

    private void OpenSearch()
    {
        SearchBar.Visibility = Visibility.Visible;
        SearchBox.Focus(FocusState.Programmatic);
        SearchBox.SelectAll();
    }

    private void CloseSearch()
    {
        SearchBar.Visibility = Visibility.Collapsed;
        SearchBox.Text = "";
        MatchCount.Text = "";
        if (_originalFindings is not null) List.Findings = _originalFindings;
    }

    private void CloseSearch_Click(object sender, RoutedEventArgs e) => CloseSearch();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        => ApplySearch(SearchBox.Text);

    private void SearchBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Escape)
        {
            CloseSearch();
            e.Handled = true;
        }
    }

    private void ApplySearch(string query)
    {
        if (_originalFindings is null) return;
        query = query.Trim();
        if (query.Length == 0)
        {
            List.Findings = _originalFindings;
            MatchCount.Text = "";
            return;
        }
        var filtered = _originalFindings.Where(f =>
            (f.Title?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
            || (f.Value?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
            || (f.Details?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
            .ToList();
        List.Findings = filtered;
        MatchCount.Text = $"{filtered.Count} / {_originalFindings.Count}";
    }
}
