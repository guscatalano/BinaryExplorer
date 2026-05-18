using System.ComponentModel;

namespace BinaryExplorer.Core;

public sealed record EmbeddedHit(
    string Type,
    long Offset,
    long? Size,            // null when size could not be determined
    string Section,
    string SuggestedExtension,
    string? Notes = null)
{
    public long EffectiveSize(long containerLength)
    {
        if (Size is long s) return Math.Min(s, containerLength - Offset);
        const long FallbackCap = 32L * 1024 * 1024;
        return Math.Min(FallbackCap, containerLength - Offset);
    }

    public bool SizeIsKnown => Size.HasValue;
    public string OffsetHex => "0x" + Offset.ToString("X8");
    public string SizeDisplay => Size is long s ? FormatBytes(s) : "unknown";

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }
}

public sealed class EmbeddedHitGroup : INotifyPropertyChanged
{
    public string Type { get; }
    public IReadOnlyList<EmbeddedHit> Hits { get; }
    public int Count => Hits.Count;
    public bool AnyInOverlay => Hits.Any(h => h.Section == "overlay");

    private bool _isExpanded;
    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (_isExpanded == value) return;
            _isExpanded = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
        }
    }

    public EmbeddedHitGroup(string type, IReadOnlyList<EmbeddedHit> hits, bool isExpanded)
    {
        Type = type;
        Hits = hits;
        _isExpanded = isExpanded;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
