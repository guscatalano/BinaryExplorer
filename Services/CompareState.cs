using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using BinaryExplorer.Core;

namespace BinaryExplorer.Services;

public sealed class CompareState : INotifyPropertyChanged
{
    public static CompareState Instance { get; } = new();
    private CompareState() { }

    private BinaryContext? _binary;
    public BinaryContext? Binary
    {
        get => _binary;
        private set { _binary = value; OnChanged(); OnChanged(nameof(IsLoaded)); OnChanged(nameof(DisplayName)); }
    }

    public bool IsLoaded => _binary is not null;
    public string DisplayName => _binary is null ? "(no file)" : Path.GetFileName(_binary.Path);

    private readonly Dictionary<string, InspectionResult> _results = new();
    public IReadOnlyDictionary<string, InspectionResult> Results => _results;

    public async Task LoadAsync(string path, CancellationToken ct = default)
    {
        Binary = new BinaryContext(path);
        _results.Clear();
        OnChanged(nameof(Results));

        var tasks = BinaryLoader.DefaultInspectors.Select(async i =>
        {
            try
            {
                var r = await i.InspectAsync(Binary, ct).ConfigureAwait(false);
                _results[r.InspectorName] = r;
            }
            catch (Exception ex)
            {
                _results[i.Name] = new InspectionResult { InspectorName = i.Name, Headline = $"{i.Name} crashed", Error = ex.ToString() };
            }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
        OnChanged(nameof(Results));
    }

    public InspectionResult? GetResult(string inspectorName)
        => _results.TryGetValue(inspectorName, out var r) ? r : null;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
