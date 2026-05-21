namespace BinaryExplorer.Services.Mcp;

/// <summary>
/// Mutable per-process MCP session state. Lets a client set a "current target"
/// binary once and then omit the 'path' argument on subsequent tool calls.
///
/// This is distinct from the file open in the WinUI3 UI (<see cref="AppState"/>):
/// the session target is explicit MCP state, the UI file is a final fallback.
/// Resolution order used by McpTools.RequirePath is:
///   explicit 'path' argument  ->  session target  ->  UI-loaded file  ->  error.
/// </summary>
public static class McpSession
{
    private static volatile string? _currentTargetPath;

    /// <summary>The explicitly set MCP session target, or null if none is set.</summary>
    public static string? CurrentTargetPath
    {
        get => _currentTargetPath;
        set => _currentTargetPath = value;
    }
}
