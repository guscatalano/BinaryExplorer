using System.Collections.Generic;
using BinaryExplorer.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace BinaryExplorer.Controls;

public sealed partial class FindingsList : UserControl
{
    public FindingsList()
    {
        InitializeComponent();
    }

    public static readonly DependencyProperty FindingsProperty =
        DependencyProperty.Register(
            nameof(Findings),
            typeof(IEnumerable<Finding>),
            typeof(FindingsList),
            new PropertyMetadata(null, OnFindingsChanged));

    public IEnumerable<Finding>? Findings
    {
        get => (IEnumerable<Finding>?)GetValue(FindingsProperty);
        set => SetValue(FindingsProperty, value);
    }

    private static void OnFindingsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((FindingsList)d).Items.ItemsSource = e.NewValue;
    }

    private async void CopyValue_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn) return;
        string? value = btn.Tag as string;
        if (string.IsNullOrEmpty(value)) return;
        try
        {
            var data = new DataPackage();
            data.SetText(value);
            Clipboard.SetContent(data);
        }
        catch { return; }

        // Brief visual confirmation: swap glyph to checkmark for ~1s.
        if (btn.Content is FontIcon icon)
        {
            string original = icon.Glyph;
            icon.Glyph = ""; // Accept
            await Task.Delay(900);
            icon.Glyph = original;
        }
    }
}
