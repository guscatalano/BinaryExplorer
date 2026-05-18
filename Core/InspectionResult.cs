namespace BinaryExplorer.Core;

public sealed class InspectionResult
{
    public string InspectorName { get; init; } = "";
    public string? Headline { get; init; }
    public IReadOnlyList<Finding> Findings { get; init; } = Array.Empty<Finding>();
    public string? Error { get; init; }
    /// <summary>Optional typed extension data for inspectors that need richer UI (e.g. extractable hits).</summary>
    public object? Payload { get; init; }
}
