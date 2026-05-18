using System.ComponentModel;
using System.Runtime.CompilerServices;
using BinaryExplorer.Analysis;
using BinaryExplorer.Core;

namespace BinaryExplorer.Services;

public sealed class AppState : INotifyPropertyChanged
{
    public static AppState Instance { get; } = new AppState();
    private AppState() { }

    private BinaryContext? _binary;
    public BinaryContext? Binary
    {
        get => _binary;
        set { _binary = value; _analysis = null; OnChanged(); OnChanged(nameof(IsLoaded)); OnChanged(nameof(DisplayName)); OnChanged(nameof(Analysis)); }
    }

    private AnalysisIndex? _analysis;
    public AnalysisIndex? Analysis => _analysis;
    public async Task<AnalysisIndex> GetOrAnalyzeAsync()
    {
        if (_analysis is not null) return _analysis;
        var ctx = _binary ?? throw new InvalidOperationException("No binary loaded.");
        _analysis = await Task.Run(() => PeAnalysis.Analyze(ctx));
        OnChanged(nameof(Analysis));
        return _analysis;
    }

    private readonly Dictionary<string, InspectionResult> _results = new();
    public IReadOnlyDictionary<string, InspectionResult> Results => _results;

    public bool IsLoaded => _binary is not null;
    public string DisplayName => _binary is null ? "No file loaded" : System.IO.Path.GetFileName(_binary.Path);

    public void SetResult(InspectionResult result)
    {
        _results[result.InspectorName] = result;
        OnChanged(nameof(Results));
    }

    public void ClearResults()
    {
        _results.Clear();
        OnChanged(nameof(Results));
    }

    public InspectionResult? GetResult(string inspectorName) =>
        _results.TryGetValue(inspectorName, out var r) ? r : null;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
