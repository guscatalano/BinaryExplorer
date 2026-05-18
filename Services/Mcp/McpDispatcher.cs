using System.Text.Json;

namespace BinaryExplorer.Services.Mcp;

internal static class McpDispatcher
{
    public static async Task<McpJsonRpcResponse?> HandleAsync(JsonElement request)
    {
        object? id = ExtractId(request);
        string method = request.TryGetProperty("method", out var m) ? m.GetString() ?? "" : "";

        try
        {
            switch (method)
            {
                case "initialize":
                    return new McpJsonRpcResponse(id, new
                    {
                        protocolVersion = "2024-11-05",
                        capabilities = new { tools = new { } },
                        serverInfo = new { name = "binary-explorer-embedded", version = "0.1.0" },
                    }, null);

                case "initialized":
                case "notifications/initialized":
                    return null;

                case "tools/list":
                    return new McpJsonRpcResponse(id, new { tools = McpTools.Describe() }, null);

                case "tools/call":
                    if (!request.TryGetProperty("params", out var p))
                        return new McpJsonRpcResponse(id, null, new McpJsonRpcError(-32602, "Missing params", null));
                    string toolName = p.GetProperty("name").GetString() ?? "";
                    var args = p.TryGetProperty("arguments", out var a) ? a : default;
                    return await McpTools.CallAsync(id, toolName, args);

                case "ping":
                    return new McpJsonRpcResponse(id, new { }, null);

                default:
                    return new McpJsonRpcResponse(id, null, new McpJsonRpcError(-32601, $"Unknown method: {method}", null));
            }
        }
        catch (Exception ex)
        {
            return new McpJsonRpcResponse(id, null,
                new McpJsonRpcError(-32000, "Server error", new { exception = ex.GetType().Name, message = ex.Message }));
        }
    }

    private static object? ExtractId(JsonElement request)
    {
        if (!request.TryGetProperty("id", out var el)) return null;
        return el.ValueKind switch
        {
            JsonValueKind.Number => el.TryGetInt64(out long l) ? l : el.GetDouble(),
            JsonValueKind.String => el.GetString(),
            _ => null,
        };
    }
}
