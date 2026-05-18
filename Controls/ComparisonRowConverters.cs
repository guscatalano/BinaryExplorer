using Microsoft.UI;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace BinaryExplorer.Controls;

public sealed class IndicatorBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Same   = new(Color.FromArgb(255, 134, 239, 172)); // green-300
    private static readonly SolidColorBrush Diff   = new(Color.FromArgb(255, 252, 165, 165)); // red-300
    private static readonly SolidColorBrush OnlyOne= new(Color.FromArgb(255, 252, 211, 77));  // amber-300

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return (value as string) switch
        {
            "=" => Same,
            "≠" => Diff,
            "◄" or "►" => OnlyOne,
            _ => Same,
        };
    }
    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
