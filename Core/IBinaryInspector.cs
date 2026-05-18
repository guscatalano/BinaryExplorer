namespace BinaryExplorer.Core;

public interface IBinaryInspector
{
    string Name { get; }
    Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default);
}
