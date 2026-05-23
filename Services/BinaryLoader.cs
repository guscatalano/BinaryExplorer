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
        new InterfacesInspector(),
        new StringsInspector(),
        new PackingInspector(),
        new TlsCallbacksInspector(),
        new PeMetadataInspector(),
        new MarkOfTheWebInspector(),
        new EmbeddedFilesInspector(),
        new VirusTotalInspector(),
        new MsiInspector(),
    };

    /// <summary>Inspectors that are happy to run against ANY file, not just PEs. PE-only inspectors are skipped when the file doesn't have an MZ header (e.g. an MSI/CFB) to avoid noisy 'invalid sections' errors.</summary>
    private static readonly HashSet<string> NonPeSafeInspectors = new(StringComparer.Ordinal)
    {
        "Language",
        "Hashes",
        "MOTW",
        "Embedded",
        "Strings",
        "VirusTotal",
        "MSI",
    };

    public static async Task LoadAsync(string path, CancellationToken ct = default)
    {
        var context = new BinaryContext(path);
        AppState.Instance.ClearResults();
        AppState.Instance.Binary = context;

        bool isPe = context.Bytes.Length >= 2 && context.Bytes[0] == 0x4D && context.Bytes[1] == 0x5A;

        var tasks = new List<Task>();
        foreach (var inspector in DefaultInspectors)
        {
            if (isPe || NonPeSafeInspectors.Contains(inspector.Name))
            {
                tasks.Add(RunOne(inspector, context, ct));
            }
            else
            {
                // A PE-only inspector against a non-PE file (e.g. an MSI): publish a
                // clean "not applicable" result up front so its page renders that
                // instead of sitting forever on "Running...".
                AppState.Instance.SetResult(new InspectionResult
                {
                    InspectorName = inspector.Name,
                    Headline = "Not applicable — not a PE executable",
                    Findings = new List<Finding>
                    {
                        new Finding(
                            inspector.Name,
                            $"The {inspector.Name} inspector only applies to PE binaries (.exe / .dll / .sys / .winmd).",
                            "This file has no 'MZ' header. For an installer database see the MSI page; "
                            + "Hashes, Strings, and Embedded Files work on any file type."),
                    },
                });
            }
        }
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
