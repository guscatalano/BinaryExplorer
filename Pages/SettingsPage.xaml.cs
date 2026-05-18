using System.Net.Http;
using BinaryExplorer.Services;
using BinaryExplorer.Services.Mcp;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace BinaryExplorer.Pages;

public sealed partial class SettingsPage : Page
{
    public SettingsPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        ReflectMcpState();
        RebuildConfigs();
        VtKeyBox.Password = Settings.VirusTotalApiKey ?? "";
        ExperimentalEtwToggle.IsOn = Settings.EnableExperimentalEtwScan;
        EmbArchivesToggle.IsOn  = Settings.EmbeddedScanArchives;
        EmbDocumentsToggle.IsOn = Settings.EmbeddedScanDocuments;
        EmbMarkupToggle.IsOn    = Settings.EmbeddedScanMarkup;
        EmbImagesToggle.IsOn    = Settings.EmbeddedScanImages;
        EmbMediaToggle.IsOn     = Settings.EmbeddedScanMedia;
        EmbCodeToggle.IsOn      = Settings.EmbeddedScanCode;
        EmbDataToggle.IsOn      = Settings.EmbeddedScanData;
    }

    private void SaveVtKey_Click(object sender, RoutedEventArgs e)
    {
        Settings.VirusTotalApiKey = VtKeyBox.Password;
        ShowVtStatus("VirusTotal API key saved.", InfoBarSeverity.Success);
    }

    private void ClearVtKey_Click(object sender, RoutedEventArgs e)
    {
        Settings.VirusTotalApiKey = null;
        VtKeyBox.Password = "";
        ShowVtStatus("VirusTotal API key cleared.", InfoBarSeverity.Informational);
    }

    private async void TestVtKey_Click(object sender, RoutedEventArgs e)
    {
        var key = VtKeyBox.Password;
        if (string.IsNullOrWhiteSpace(key))
        {
            ShowVtStatus("Enter a key first.", InfoBarSeverity.Warning);
            return;
        }
        ShowVtStatus("Testing key against virustotal.com...", InfoBarSeverity.Informational);
        try
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Add("x-apikey", key);
            var resp = await http.GetAsync("https://www.virustotal.com/api/v3/users/current");
            if (resp.IsSuccessStatusCode) ShowVtStatus("Key is valid.", InfoBarSeverity.Success);
            else if ((int)resp.StatusCode == 401) ShowVtStatus("Key rejected by VirusTotal (401).", InfoBarSeverity.Error);
            else ShowVtStatus($"VirusTotal returned {(int)resp.StatusCode}.", InfoBarSeverity.Warning);
        }
        catch (Exception ex)
        {
            ShowVtStatus($"Network error: {ex.Message}", InfoBarSeverity.Error);
        }
    }

    private void ShowVtStatus(string message, InfoBarSeverity severity)
    {
        VtStatus.Severity = severity;
        VtStatus.Message = message;
        VtStatus.IsOpen = true;
    }

    private void ExperimentalEtwToggle_Toggled(object sender, RoutedEventArgs e)
    {
        Settings.EnableExperimentalEtwScan = ExperimentalEtwToggle.IsOn;
    }

    private void McpStart_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            int port = (int)McpPortBox.Value;
            McpHttpServer.Instance.Start(port);
            ReflectMcpState();
            ShowMcpStatus($"MCP server running on http://localhost:{port}/", InfoBarSeverity.Success);
        }
        catch (Exception ex)
        {
            ShowMcpStatus("Failed to start: " + ex.Message, InfoBarSeverity.Error);
        }
    }

    private void McpStop_Click(object sender, RoutedEventArgs e)
    {
        McpHttpServer.Instance.Stop();
        ReflectMcpState();
        ShowMcpStatus("Stopped.", InfoBarSeverity.Informational);
    }

    private void ReflectMcpState()
    {
        bool running = McpHttpServer.Instance.IsRunning;
        McpStartButton.IsEnabled = !running;
        McpStopButton.IsEnabled = running;
        if (running && McpHttpServer.Instance.Port is int p)
        {
            McpStatusLabel.Text = $"listening on :{p}";
            McpUrlBox.Text = $"http://localhost:{p}/";
            McpUrlBox.Visibility = Visibility.Visible;
        }
        else
        {
            McpStatusLabel.Text = "stopped";
            McpUrlBox.Visibility = Visibility.Collapsed;
        }
    }

    private void RebuildConfigs()
    {
        int port = (int)McpPortBox.Value;
        string url = $"http://localhost:{port}/";

        CfgVsCodeHttpBox.Text =
            "{\r\n" +
            "  \"servers\": {\r\n" +
            "    \"binary-explorer\": {\r\n" +
            "      \"type\": \"http\",\r\n" +
            $"      \"url\": \"{url}\"\r\n" +
            "    }\r\n" +
            "  }\r\n" +
            "}";

        CfgClaudeCodeBox.Text =
            $"claude mcp add --transport http binary-explorer {url}";

        CfgCurlBox.Text =
            $"curl -s {url}tools\r\n" +
            $"curl -s {url} -H \"Content-Type: application/json\" -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'";
    }

    private void CopyConfig_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string key) return;
        TextBox? box = key switch
        {
            "VsCodeHttp" => CfgVsCodeHttpBox,
            "ClaudeCode" => CfgClaudeCodeBox,
            "Curl"       => CfgCurlBox,
            _ => null,
        };
        if (box is null || string.IsNullOrEmpty(box.Text)) return;
        var dp = new Windows.ApplicationModel.DataTransfer.DataPackage();
        dp.SetText(box.Text);
        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(dp);
    }

    private void ShowMcpStatus(string message, InfoBarSeverity severity)
    {
        McpStatusBar.Severity = severity;
        McpStatusBar.Message = message;
        McpStatusBar.IsOpen = true;
    }

    private void EmbCategory_Toggled(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleSwitch ts || ts.Tag is not string tag) return;
        switch (tag)
        {
            case "Archives":  Settings.EmbeddedScanArchives  = ts.IsOn; break;
            case "Documents": Settings.EmbeddedScanDocuments = ts.IsOn; break;
            case "Markup":    Settings.EmbeddedScanMarkup    = ts.IsOn; break;
            case "Images":    Settings.EmbeddedScanImages    = ts.IsOn; break;
            case "Media":     Settings.EmbeddedScanMedia     = ts.IsOn; break;
            case "Code":      Settings.EmbeddedScanCode      = ts.IsOn; break;
            case "Data":      Settings.EmbeddedScanData      = ts.IsOn; break;
        }
    }
}
