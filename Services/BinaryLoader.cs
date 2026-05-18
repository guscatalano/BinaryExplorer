using BinaryExplorer.Core;
using BinaryExplorer.Inspectors;

namespace BinaryExplorer.Services;

public static class BinaryLoader
{
    public static IBinaryInspector[] DefaultInspectors { get; } = new IBinaryInspector[]
    {
        new LanguageInspector(),
        new VersionInfoInspector(),
        new SignatureInspector(),
        new HashesInspector(),
        new RichHeaderInspector(),
        new DebugInfoInspector(),
        new EtwInspector(),
        new DependenciesInspector(),
        new CapabilitiesInspector(),
        new StringsInspector(),
        new PackingInspector(),
        new TlsCallbacksInspector(),
        new PeMetadataInspector(),
        new MarkOfTheWebInspector(),
        new EmbeddedFilesInspector(),
        new VirusTotalInspector(),
    };

    public static async Task LoadAsync(string path, CancellationToken ct = default)
    {
        var context = new BinaryContext(path);
        AppState.Instance.ClearResults();
        AppState.Instance.Binary = context;

        var tasks = DefaultInspectors.Select(i => RunOne(i, context, ct)).ToArray();
        await Task.WhenAll(tasks);
    }

    public static async Task RescanAsync(string inspectorName, CancellationToken ct = default)
    {
        var ctx = AppState.Instance.Binary;
        if (ctx is null) return;
        var inspector = DefaultInspectors.FirstOrDefault(i =>
            string.Equals(i.Name, inspectorName, StringComparison.OrdinalIgnoreCase));
        if (inspector is null) return;
        await RunOne(inspector, ctx, ct);
    }

    private static async Task RunOne(IBinaryInspector inspector, BinaryContext ctx, CancellationToken ct)
    {
        try
        {
            var result = await inspector.InspectAsync(ctx, ct).ConfigureAwait(false);
            AppState.Instance.SetResult(result);
        }
        catch (Exception ex)
        {
            AppState.Instance.SetResult(new InspectionResult
            {
                InspectorName = inspector.Name,
                Headline = $"{inspector.Name} crashed",
                Error = ex.ToString(),
            });
        }
    }
}
