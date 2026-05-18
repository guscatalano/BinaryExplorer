using Microsoft.UI;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace BinaryExplorer.Controls;

public sealed class ConfirmedToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Confirmed = new(Color.FromArgb(255, 245, 158, 11)); // amber-500
    private static readonly SolidColorBrush Discovered = new(Color.FromArgb(255, 113, 113, 122)); // zinc-500

    public object Convert(object value, Type targetType, object parameter, string language)
        => value is bool b && b ? Confirmed : Discovered;
    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}

public sealed class RvaToHexConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return value switch
        {
            uint u => "0x" + u.ToString("X"),
            int i => "0x" + i.ToString("X"),
            ulong ul => "0x" + ul.ToString("X"),
            _ => value?.ToString() ?? "",
        };
    }
    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
