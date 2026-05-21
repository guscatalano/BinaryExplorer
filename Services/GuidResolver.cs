using Microsoft.Win32;

namespace BinaryExplorer.Services;

/// <summary>
/// Looks up GUIDs in the local Windows registry to identify CLSIDs (COM classes),
/// IIDs (interfaces), AppIDs, and TypeLibs.
/// </summary>
public static class GuidResolver
{
    public sealed record GuidLookup(
        string Guid,
        string? Category,   // "CLSID" / "IID" / "AppID" / "TypeLib" / null
        string? Name,
        string? ProgID,
        string? InprocServer,
        string? LocalServer,
        string? AppId,
        string? ThreadingModel,
        string? Hive);

    private static readonly string[] Hives = new[]
    {
        @"SOFTWARE\Classes",
        @"SOFTWARE\WOW6432Node\Classes",
    };

    public static GuidLookup Resolve(string guid)
    {
        string normalized = NormalizeGuid(guid);
        if (string.IsNullOrEmpty(normalized))
            return new GuidLookup(guid, null, null, null, null, null, null, null, null);

        string bracketed = "{" + normalized + "}";

        // HKLM + HKCU.
        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            foreach (var hive in Hives)
            {
                var clsid = TryClsid(root, hive, bracketed);
                if (clsid is not null) return clsid;
            }
            foreach (var hive in Hives)
            {
                var iface = TryInterface(root, hive, bracketed);
                if (iface is not null) return iface;
            }
            foreach (var hive in Hives)
            {
                var appid = TryAppId(root, hive, bracketed);
                if (appid is not null) return appid;
            }
            foreach (var hive in Hives)
            {
                var tlb = TryTypeLib(root, hive, bracketed);
                if (tlb is not null) return tlb;
            }
        }
        return new GuidLookup(bracketed, null, null, null, null, null, null, null, null);
    }

    private static string NormalizeGuid(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        s = s.Trim().TrimStart('{').TrimEnd('}');
        if (Guid.TryParse(s, out var g)) return g.ToString("D");
        return "";
    }

    private static GuidLookup? TryClsid(RegistryKey root, string hive, string bracketedGuid)
    {
        using var key = root.OpenSubKey($@"{hive}\CLSID\{bracketedGuid}");
        if (key is null) return null;
        string? name = key.GetValue("") as string;
        string? appId = key.GetValue("AppID") as string;
        string? inproc = null, threading = null, localServer = null, progId = null;

        using (var ips = key.OpenSubKey("InprocServer32"))
        {
            if (ips is not null)
            {
                inproc = ips.GetValue("") as string;
                threading = ips.GetValue("ThreadingModel") as string;
            }
        }
        using (var ls = key.OpenSubKey("LocalServer32"))
            if (ls is not null) localServer = ls.GetValue("") as string;
        using (var pid = key.OpenSubKey("ProgID"))
            if (pid is not null) progId = pid.GetValue("") as string;

        return new GuidLookup(bracketedGuid, "CLSID", name, progId, inproc, localServer, appId, threading,
            $"{root.Name}\\{hive}");
    }

    private static GuidLookup? TryInterface(RegistryKey root, string hive, string bracketedGuid)
    {
        using var key = root.OpenSubKey($@"{hive}\Interface\{bracketedGuid}");
        if (key is null) return null;
        string? name = key.GetValue("") as string;
        return new GuidLookup(bracketedGuid, "IID", name, null, null, null, null, null,
            $"{root.Name}\\{hive}");
    }

    private static GuidLookup? TryAppId(RegistryKey root, string hive, string bracketedGuid)
    {
        using var key = root.OpenSubKey($@"{hive}\AppID\{bracketedGuid}");
        if (key is null) return null;
        string? name = key.GetValue("") as string;
        string? localService = key.GetValue("LocalService") as string;
        return new GuidLookup(bracketedGuid, "AppID", name, null, null, localService, bracketedGuid, null,
            $"{root.Name}\\{hive}");
    }

    private static GuidLookup? TryTypeLib(RegistryKey root, string hive, string bracketedGuid)
    {
        using var key = root.OpenSubKey($@"{hive}\TypeLib\{bracketedGuid}");
        if (key is null) return null;
        // Walk first version sub-key for a name.
        string? name = null;
        foreach (var versionName in key.GetSubKeyNames())
        {
            using var vkey = key.OpenSubKey(versionName);
            if (vkey is null) continue;
            name = vkey.GetValue("") as string;
            if (!string.IsNullOrEmpty(name)) break;
        }
        return new GuidLookup(bracketedGuid, "TypeLib", name, null, null, null, null, null,
            $"{root.Name}\\{hive}");
    }
}
