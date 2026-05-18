using Windows.Storage;

namespace BinaryExplorer.Services;

public static class Settings
{
    private const string VtKeyName = "VirusTotalApiKey";
    private const string ExperimentalEtwScanName = "EnableExperimentalEtwScan";

    public static string? VirusTotalApiKey
    {
        get => ApplicationData.Current.LocalSettings.Values[VtKeyName] as string;
        set
        {
            if (string.IsNullOrWhiteSpace(value))
                ApplicationData.Current.LocalSettings.Values.Remove(VtKeyName);
            else
                ApplicationData.Current.LocalSettings.Values[VtKeyName] = value;
        }
    }

    public static bool EnableExperimentalEtwScan
    {
        get => ApplicationData.Current.LocalSettings.Values[ExperimentalEtwScanName] is bool b && b;
        set => ApplicationData.Current.LocalSettings.Values[ExperimentalEtwScanName] = value;
    }

    private static bool GetBool(string key, bool defaultValue) =>
        ApplicationData.Current.LocalSettings.Values[key] is bool b ? b : defaultValue;
    private static void SetBool(string key, bool value) =>
        ApplicationData.Current.LocalSettings.Values[key] = value;

    public static bool EmbeddedScanArchives  { get => GetBool("EmbeddedScan.Archives",  true);  set => SetBool("EmbeddedScan.Archives",  value); }
    public static bool EmbeddedScanDocuments { get => GetBool("EmbeddedScan.Documents", true);  set => SetBool("EmbeddedScan.Documents", value); }
    public static bool EmbeddedScanMarkup    { get => GetBool("EmbeddedScan.Markup",    true);  set => SetBool("EmbeddedScan.Markup",    value); }
    public static bool EmbeddedScanImages    { get => GetBool("EmbeddedScan.Images",    true);  set => SetBool("EmbeddedScan.Images",    value); }
    public static bool EmbeddedScanMedia     { get => GetBool("EmbeddedScan.Media",     true);  set => SetBool("EmbeddedScan.Media",     value); }
    public static bool EmbeddedScanCode      { get => GetBool("EmbeddedScan.Code",      true);  set => SetBool("EmbeddedScan.Code",      value); }
    public static bool EmbeddedScanData      { get => GetBool("EmbeddedScan.Data",      true);  set => SetBool("EmbeddedScan.Data",      value); }

    public static string YaraExePath
    {
        get => ApplicationData.Current.LocalSettings.Values["Yara.ExePath"] as string ?? "yara.exe";
        set => ApplicationData.Current.LocalSettings.Values["Yara.ExePath"] = string.IsNullOrWhiteSpace(value) ? "yara.exe" : value;
    }

    public static string? YaraRulesPath
    {
        get => ApplicationData.Current.LocalSettings.Values["Yara.RulesPath"] as string;
        set
        {
            if (string.IsNullOrWhiteSpace(value))
                ApplicationData.Current.LocalSettings.Values.Remove("Yara.RulesPath");
            else
                ApplicationData.Current.LocalSettings.Values["Yara.RulesPath"] = value;
        }
    }
}
