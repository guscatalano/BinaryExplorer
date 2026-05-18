namespace BinaryExplorer.Core;

public sealed record ComparisonRow(string Title, string? LeftValue, string? RightValue)
{
    public bool BothPresent => LeftValue is not null && RightValue is not null;
    public bool Equal       => BothPresent && string.Equals(LeftValue, RightValue, StringComparison.Ordinal);
    public bool Different   => BothPresent && !Equal;
    public bool OnlyLeft    => LeftValue is not null && RightValue is null;
    public bool OnlyRight   => LeftValue is null && RightValue is not null;

    public string Indicator => this switch
    {
        { Equal: true }     => "=",
        { Different: true } => "≠",
        { OnlyLeft: true }  => "◄",
        { OnlyRight: true } => "►",
        _ => "",
    };
}
