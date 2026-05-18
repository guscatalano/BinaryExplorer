using System.Net;
using System.Text;
using System.Text.Json;

namespace BinaryExplorer.Services.Mcp;

/// <summary>
/// Embedded MCP server. Speaks JSON-RPC 2.0 over HTTP POST. Tools are implemented
/// inside the running WinUI3 process, so they have access to the same inspector
/// surface (and could later see live AppState if we want).
/// </summary>
public sealed class McpHttpServer
{
    public static McpHttpServer Instance { get; } = new();
    private McpHttpServer() { }

    internal static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public bool IsRunning => _listener?.IsListening == true;
    public int? Port { get; private set; }

    public void Start(int port)
    {
        if (IsRunning) throw new InvalidOperationException("Already running.");
        var l = new HttpListener();
        l.Prefixes.Add($"http://localhost:{port}/");
        l.Start();
        _listener = l;
        _cts = new CancellationTokenSource();
        Port = port;
        _loop = Task.Run(() => AcceptLoopAsync(l, _cts.Token));
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try
        {
            _listener?.Stop();
            _listener?.Close();
        }
        catch { }
        _listener = null;
        _cts = null;
        _loop = null;
        Port = null;
    }

    private async Task AcceptLoopAsync(HttpListener l, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = await l.GetContextAsync(); }
            catch { break; }
            _ = Task.Run(() => HandleAsync(ctx), ct);
        }
    }

    private static async Task HandleAsync(HttpListenerContext ctx)
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

            if (ctx.Request.HttpMethod == "GET"
                && string.Equals(ctx.Request.Url?.AbsolutePath, "/tools", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonAsync(ctx, 200, JsonSerializer.Serialize(new { tools = McpTools.Describe() }, JsonOpts));
                return;
            }

            if (ctx.Request.HttpMethod != "POST")
            {
                ctx.Response.StatusCode = 405;
                await WriteTextAsync(ctx, "POST a JSON-RPC 2.0 body, or GET /tools to list tools.");
                return;
            }

            string requestBody;
            using (var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding ?? Encoding.UTF8))
                requestBody = await reader.ReadToEndAsync();

            if (string.IsNullOrWhiteSpace(requestBody))
            {
                await WriteJsonAsync(ctx, 400, JsonSerializer.Serialize(
                    new McpJsonRpcResponse(null, null, new McpJsonRpcError(-32700, "Empty request body", null)),
                    JsonOpts));
                return;
            }

            McpJsonRpcResponse? response;
            try
            {
                using var doc = JsonDocument.Parse(requestBody);
                response = await McpDispatcher.HandleAsync(doc.RootElement.Clone());
            }
            catch (Exception ex)
            {
                response = new McpJsonRpcResponse(null, null, new McpJsonRpcError(-32700, "Parse error: " + ex.Message, null));
            }

            if (response is null)
            {
                ctx.Response.StatusCode = 204;
                ctx.Response.Close();
                return;
            }
            await WriteJsonAsync(ctx, 200, JsonSerializer.Serialize(response, JsonOpts));
        }
        catch (Exception ex)
        {
            try { ctx.Response.StatusCode = 500; await WriteTextAsync(ctx, ex.Message); } catch { }
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

internal sealed record McpJsonRpcResponse(
    object? id,
    object? result,
    McpJsonRpcError? error)
{
    public string jsonrpc => "2.0";
}

internal sealed record McpJsonRpcError(int code, string message, object? data);
