namespace BinaryExplorer.Core;

public enum Severity
{
    Info,
    Warning,
    Error,
}

public sealed record Finding(
    string Title,
    string? Value = null,
    string? Details = null,
    Severity Severity = Severity.Info);
