using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;

namespace BinaryExplorer;

public partial class App : Application
{
    public static Window? MainWindow { get; private set; }

    /// <summary>
    /// Plain-text startup / crash log at a fixed, easy-to-find location so a
    /// reporter can attach it to a bug report regardless of packaged vs
    /// unpackaged install. Path: %USERPROFILE%\.binexp-startup.log
    /// </summary>
    private static string LogPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".binexp-startup.log");

    public App()
    {
        // Hook unhandled-exception sinks BEFORE InitializeComponent — any failure
        // there should still be captured.
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            AppendLog($"AppDomain.UnhandledException  terminating={e.IsTerminating}\n{e.ExceptionObject}");
        TaskScheduler.UnobservedTaskException += (_, e) =>
            AppendLog($"TaskScheduler.UnobservedTaskException\n{e.Exception}");

        AppendStartupRecord();

        InitializeComponent();

        UnhandledException += (_, e) =>
            AppendLog($"Application.UnhandledException  message=\"{e.Message}\"\n{e.Exception}");
    }

    protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
    {
        try
        {
            MainWindow = new MainWindow();
            MainWindow.Activate();
            AppendLog("MainWindow activated");
        }
        catch (Exception ex)
        {
            AppendLog($"OnLaunched threw\n{ex}");
            throw;
        }
    }

    private static void AppendStartupRecord()
    {
        try
        {
            string version = typeof(App).Assembly.GetName().Version?.ToString() ?? "?";
            string os = Environment.OSVersion.VersionString;
            string osArch = RuntimeInformation.OSArchitecture.ToString();
            string procArch = RuntimeInformation.ProcessArchitecture.ToString();
            string runtime = RuntimeInformation.FrameworkDescription;
            string pkg;
            try { pkg = Windows.ApplicationModel.Package.Current?.Id?.FullName ?? "(none)"; }
            catch { pkg = "(unpackaged)"; }

            AppendLog(
                "--- launch ---\n" +
                $"  app:       BinaryExplorer {version}\n" +
                $"  os:        {os}  ({osArch})\n" +
                $"  process:   {procArch}\n" +
                $"  runtime:   {runtime}\n" +
                $"  package:   {pkg}");
        }
        catch { /* best effort */ }
    }

    private static void AppendLog(string text)
    {
        try
        {
            // Keep the file from growing forever — single-launch sessions are small,
            // but a long-running dev loop could accumulate. Truncate at 256 KB.
            try
            {
                var fi = new FileInfo(LogPath);
                if (fi.Exists && fi.Length > 256 * 1024)
                    File.WriteAllText(LogPath, "(log truncated)\n");
            }
            catch { /* ignore */ }

            string line = $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {text}\n";
            File.AppendAllText(LogPath, line);
        }
        catch { /* best effort — never let logging itself crash the app */ }
    }
}
