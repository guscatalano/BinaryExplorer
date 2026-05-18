using System.Text.Json;

namespace BinaryExplorer.Mcp;

internal static class Dispatcher
{
    public static async Task<JsonRpcResponse?> HandleAsync(JsonElement request)
    {
        object? id = ExtractId(request);
        string method = request.TryGetProperty("method", out var m) ? m.GetString() ?? "" : "";

        try
        {
            switch (method)
            {
                case "initialize":
                    return new JsonRpcResponse(id, new
                    {
                        protocolVersion = "2024-11-05",
                        capabilities = new { tools = new { } },
                        serverInfo = new { name = "binary-explorer", version = "0.1.0" },
                    }, null);

                case "initialized":
                case "notifications/initialized":
                    return null;  // notification — no response

                case "tools/list":
                    return new JsonRpcResponse(id, new { tools = Tools.Describe() }, null);

                case "tools/call":
                    if (!request.TryGetProperty("params", out var p))
                        return new JsonRpcResponse(id, null, new JsonRpcError(-32602, "Missing params", null));

                    string toolName = p.GetProperty("name").GetString() ?? "";
                    var args = p.TryGetProperty("arguments", out var a) ? a : default;
                    return await Tools.CallAsync(id, toolName, args);

                case "ping":
                    return new JsonRpcResponse(id, new { }, null);

                default:
                    return new JsonRpcResponse(id, null, new JsonRpcError(-32601, $"Unknown method: {method}", null));
            }
        }
        catch (Exception ex)
        {
            return new JsonRpcResponse(id, null, new JsonRpcError(-32000, "Server error", new { exception = ex.GetType().Name, message = ex.Message }));
        }
    }

    private static object? ExtractId(JsonElement request)
    {
        if (!request.TryGetProperty("id", out var el)) return null;
        return el.ValueKind switch
        {
            JsonValueKind.Number => el.TryGetInt64(out long l) ? l : el.GetDouble(),
            JsonValueKind.String => el.GetString(),
            JsonValueKind.Null => null,
            _ => null,
        };
    }
}
