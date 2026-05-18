using System.Net;
using System.Text;
using System.Text.Json;

namespace BinaryExplorer.Mcp;

internal static class Program
{
    internal static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    public static async Task<int> Main(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--version":
                    Console.WriteLine("be-mcp 0.1.0");
                    return 0;
                case "--help":
                    PrintHelp();
                    return 0;
                case "--http":
                    if (i + 1 >= args.Length || !int.TryParse(args[i + 1], out int port) || port <= 0 || port > 65535)
                    {
                        Console.Error.WriteLine("--http requires a TCP port (1..65535).");
                        return 2;
                    }
                    return await RunHttpAsync(port);
            }
        }

        return await RunStdioAsync();
    }

    private static void PrintHelp()
    {
        Console.WriteLine("BinaryExplorer MCP server.");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  be-mcp                 line-delimited JSON-RPC over stdio (default)");
        Console.WriteLine("  be-mcp --http PORT     listen for JSON-RPC POSTs on http://localhost:PORT/");
        Console.WriteLine("  be-mcp --version");
        Console.WriteLine();
        Console.WriteLine("Tools: pe_info, hashes, imports, exports, strings, signature");
    }

    private static async Task<int> RunStdioAsync()
    {
        Console.OutputEncoding = Encoding.UTF8;
        var stdin = Console.In;
        var stdout = Console.Out;

        string? line;
        while ((line = await stdin.ReadLineAsync()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            JsonRpcResponse? response;
            try
            {
                using var doc = JsonDocument.Parse(line);
                response = await Dispatcher.HandleAsync(doc.RootElement.Clone());
            }
            catch (Exception ex)
            {
                response = new JsonRpcResponse(null, null, new JsonRpcError(-32700, "Parse error: " + ex.Message, null));
            }

            if (response is not null)
            {
                await stdout.WriteLineAsync(JsonSerializer.Serialize(response, JsonOpts));
                await stdout.FlushAsync();
            }
        }
        return 0;
    }

    private static async Task<int> RunHttpAsync(int port)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://localhost:{port}/");
        try { listener.Start(); }
        catch (HttpListenerException ex)
        {
            Console.Error.WriteLine($"Failed to bind http://localhost:{port}/: {ex.Message}");
            return 1;
        }
        Console.Error.WriteLine($"be-mcp listening on http://localhost:{port}/   (POST JSON-RPC 2.0 to any path)");
        Console.Error.WriteLine($"   GET /tools             — JSON list of tool descriptors");
        Console.Error.WriteLine($"   POST /                 — JSON-RPC request body");

        while (true)
        {
            HttpListenerContext ctx;
            try { ctx = await listener.GetContextAsync(); }
            catch { break; }
            _ = HandleHttpAsync(ctx);
        }
        return 0;
    }

    private static async Task HandleHttpAsync(HttpListenerContext ctx)
    {
        try
        {
            ctx.Response.Headers.Add("Access-Control-Allow-Origin", "*");
            ctx.Response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            ctx.Response.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

            if (ctx.Request.HttpMethod == "OPTIONS")
            {
                ctx.Response.StatusCode = 204;
                ctx.Response.Close();
                return;
            }

            // Convenience: GET /tools returns the tool descriptors as plain JSON.
            if (ctx.Request.HttpMethod == "GET" &&
                string.Equals(ctx.Request.Url?.AbsolutePath, "/tools", StringComparison.OrdinalIgnoreCase))
            {
                var body = JsonSerializer.Serialize(new { tools = Tools.Describe() }, JsonOpts);
                await WriteJsonAsync(ctx, 200, body);
                return;
            }

            if (ctx.Request.HttpMethod != "POST")
            {
                ctx.Response.StatusCode = 405;
                await WriteTextAsync(ctx, "Use POST with a JSON-RPC 2.0 body, or GET /tools to list tools.");
                return;
            }

            string requestBody;
            using (var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding ?? Encoding.UTF8))
                requestBody = await reader.ReadToEndAsync();

            if (string.IsNullOrWhiteSpace(requestBody))
            {
                await WriteJsonAsync(ctx, 400,
                    JsonSerializer.Serialize(new JsonRpcResponse(null, null, new JsonRpcError(-32700, "Empty request body", null)), JsonOpts));
                return;
            }

            JsonRpcResponse? response;
            try
            {
                using var doc = JsonDocument.Parse(requestBody);
                response = await Dispatcher.HandleAsync(doc.RootElement.Clone());
            }
            catch (Exception ex)
            {
                response = new JsonRpcResponse(null, null, new JsonRpcError(-32700, "Parse error: " + ex.Message, null));
            }

            if (response is null)
            {
                ctx.Response.StatusCode = 204;
                ctx.Response.Close();
                return;
            }

            var respBody = JsonSerializer.Serialize(response, JsonOpts);
            await WriteJsonAsync(ctx, 200, respBody);
        }
        catch (Exception ex)
        {
            try
            {
                ctx.Response.StatusCode = 500;
                await WriteTextAsync(ctx, ex.Message);
            }
            catch { }
        }
    }

    private static async Task WriteJsonAsync(HttpListenerContext ctx, int status, string body)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        var bytes = Encoding.UTF8.GetBytes(body);
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    private static async Task WriteTextAsync(HttpListenerContext ctx, string body)
    {
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(body);
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }
}

internal sealed record JsonRpcResponse(
    object? id,
    object? result,
    JsonRpcError? error)
{
    public string jsonrpc => "2.0";
}

internal sealed record JsonRpcError(int code, string message, object? data);
