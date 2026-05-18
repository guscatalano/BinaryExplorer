namespace BinaryExplorer.Analysis;

public sealed record FunctionInfo(
    uint Rva,
    string Name,
    bool Confirmed,           // entry/exports/TLS = true; pure call-target heuristic = false
    string? Section);

public sealed class AnalysisIndex
{
    public int Bitness { get; init; }
    public ulong ImageBase { get; init; }
    public bool Supported { get; init; }

    // Sorted by RVA. Use AddOrUpgrade to ensure unique by RVA with priority for confirmed.
    public List<FunctionInfo> Functions { get; } = new();

    // Xrefs: TargetVa -> sorted list of SourceVa.
    public Dictionary<ulong, List<ulong>> Xrefs { get; } = new();

    public void AddOrUpgrade(FunctionInfo fn)
    {
        for (int i = 0; i < Functions.Count; i++)
        {
            if (Functions[i].Rva == fn.Rva)
            {
                // Prefer confirmed name + section if missing.
                var existing = Functions[i];
                Functions[i] = existing with
                {
                    Name = existing.Confirmed ? existing.Name : fn.Confirmed ? fn.Name : existing.Name,
                    Confirmed = existing.Confirmed || fn.Confirmed,
                    Section = existing.Section ?? fn.Section,
                };
                return;
            }
        }
        Functions.Add(fn);
    }

    public void AddXref(ulong targetVa, ulong sourceVa)
    {
        if (!Xrefs.TryGetValue(targetVa, out var list))
            Xrefs[targetVa] = list = new List<ulong>(4);
        if (list.Count < 64 && !list.Contains(sourceVa))
            list.Add(sourceVa);
    }

    public void SortByRva()
    {
        Functions.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        foreach (var kv in Xrefs.Values) kv.Sort();
    }
}
