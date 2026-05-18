using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using BinaryExplorer.Core;
using BinaryExplorer.Inspectors;
using Iced.Intel;

namespace BinaryExplorer.Services.Mcp;

/// <summary>
/// MCP tool definitions. Reuses the existing inspector classes so anything the
/// WinUI3 UI shows is also reachable from MCP clients.
/// </summary>
internal static class McpTools
{
    public static object[] Describe() => new object[]
    {
        new
        {
            name = "inspect",
            description = "Run inspectors against a Windows PE binary on disk and return findings. With no 'inspector' arg, runs every inspector and returns each one's headline plus its first 20 findings (drill in with 'inspector' to get the full list).",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string", description = "Filesystem path to a Windows PE binary." },
                    inspector = new
                    {
                        type = "string",
                        description = "Optional. Run only this inspector. Names: " + string.Join(", ", BinaryLoader.DefaultInspectors.Select(i => i.Name)),
                    },
                },
                required = new[] { "path" },
            },
        },
        new
        {
            name = "list_inspectors",
            description = "List all available inspector names.",
            inputSchema = new { type = "object", properties = new { } },
        },
        new
        {
            name = "disassemble",
            description = "Disassemble x86/x64 native code starting at an RVA inside the binary. Honors MSVC ret/padding so by default stops at end of function.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string", description = "Filesystem path to a Windows PE binary." },
                    rva = new { type = "string", description = "Starting RVA in hex (e.g. '0x1A30') or decimal." },
                    count = new { type = "integer", description = "Max instructions to decode. Default 64.", minimum = 1, maximum = 4096 },
                    stopAtRet = new { type = "boolean", description = "Stop at the first ret instruction. Default true." },
                },
                required = new[] { "path", "rva" },
            },
        },
        new
        {
            name = "read_bytes",
            description = "Return a hex+ASCII dump of bytes at a file offset inside the binary.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    offset = new { type = "string", description = "File offset in hex (0x...) or decimal." },
                    length = new { type = "integer", description = "Number of bytes (default 256, max 65536).", minimum = 1, maximum = 65536 },
                },
                required = new[] { "path", "offset" },
            },
        },
    };

    public static async Task<McpJsonRpcResponse> CallAsync(object? id, string name, JsonElement args)
    {
        try
        {
            object? payload = name switch
            {
                "list_inspectors" => new { inspectors = BinaryLoader.DefaultInspectors.Select(i => i.Name).ToArray() },
                "inspect"      => await InspectAsync(args),
                "disassemble"  => await Task.Run(() => Disassemble(args)),
                "read_bytes"   => await Task.Run(() => ReadBytes(args)),
                _ => null,
            };
            if (payload is null) return ErrorContent(id, $"Unknown tool: {name}");

            string text = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
            return new McpJsonRpcResponse(id, new
            {
                content = new object[] { new { type = "text", text } },
            }, null);
        }
        catch (Exception ex)
        {
            return ErrorContent(id, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static McpJsonRpcResponse ErrorContent(object? id, string text) =>
        new(id, new { content = new object[] { new { type = "text", text } }, isError = true }, null);

    private static async Task<object> InspectAsync(JsonElement args)
    {
        string path = RequirePath(args);
        var ctx = new BinaryContext(path);

        string? requested = args.TryGetProperty("inspector", out var ie) && ie.ValueKind == JsonValueKind.String
            ? ie.GetString()
            : null;

        if (!string.IsNullOrWhiteSpace(requested))
        {
            var match = BinaryLoader.DefaultInspectors.FirstOrDefault(i =>
                string.Equals(i.Name, requested, StringComparison.OrdinalIgnoreCase));
            if (match is null)
            {
                return new
                {
                    error = $"Unknown inspector '{requested}'.",
                    available = BinaryLoader.DefaultInspectors.Select(i => i.Name).ToArray(),
                };
            }
            var r = await match.InspectAsync(ctx).ConfigureAwait(false);
            return new
            {
                path = ctx.Path,
                inspector = r.InspectorName,
                headline = r.Headline,
                error = r.Error,
                findings = r.Findings.Select(f => new
                {
                    f.Title,
                    f.Value,
                    f.Details,
                    severity = f.Severity.ToString(),
                }).ToArray(),
            };
        }

        // Run all inspectors in parallel.
        var inspectors = BinaryLoader.DefaultInspectors;
        var tasks = inspectors.Select(i => i.InspectAsync(ctx)).ToArray();
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        const int PreviewCap = 20;
        return new
        {
            path = ctx.Path,
            sizeBytes = ctx.Bytes.LongLength,
            results = results.Select(r => new
            {
                inspector = r.InspectorName,
                headline = r.Headline,
                error = r.Error,
                findingCount = r.Findings.Count,
                findings = r.Findings.Take(PreviewCap).Select(f => new
                {
                    f.Title,
                    f.Value,
                    severity = f.Severity.ToString(),
                }).ToArray(),
                truncated = r.Findings.Count > PreviewCap,
            }).ToArray(),
        };
    }

    private static object Disassemble(JsonElement args)
    {
        string path = RequirePath(args);
        if (!TryParseNumber(args.GetProperty("rva"), out long rvaLong))
            return new { error = "Couldn't parse 'rva'." };
        uint rva = (uint)rvaLong;
        int count = args.TryGetProperty("count", out var ce) && ce.TryGetInt32(out int c)
            ? Math.Clamp(c, 1, 4096) : 64;
        bool stopAtRet = !args.TryGetProperty("stopAtRet", out var se) || se.ValueKind != JsonValueKind.False;

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader ?? throw new InvalidOperationException("Not a PE file.");
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = $"Unsupported machine: {machine}. Disassembly is x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        ulong imageBase = opt.ImageBase;

        if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int fileOff))
            return new { error = $"RVA 0x{rva:X} doesn't map to any section." };

        var reader = new ByteArrayCodeReader(ctx.Bytes, fileOff, ctx.Bytes.Length - fileOff);
        var decoder = Iced.Intel.Decoder.Create(bitness, reader);
        decoder.IP = imageBase + rva;
        var formatter = new MasmFormatter();
        formatter.Options.DigitSeparator = "";

        var instructions = new List<object>();
        int produced = 0;
        while (produced < count)
        {
            ulong ip = decoder.IP;
            decoder.Decode(out var instr);
            var output = new StringOutput();
            formatter.Format(instr, output);
            int len = instr.Length;
            var hex = new StringBuilder(len * 3);
            for (int i = 0; i < len; i++)
            {
                hex.Append(ctx.Bytes[fileOff + (int)(ip - (imageBase + rva)) + i].ToString("X2"));
                if (i + 1 < len) hex.Append(' ');
            }
            instructions.Add(new
            {
                ip = "0x" + ip.ToString("X16"),
                bytes = hex.ToString(),
                text = output.ToString(),
                isInvalid = instr.IsInvalid,
                flowControl = instr.FlowControl.ToString(),
            });
            produced++;
            if (instr.IsInvalid) break;
            if (stopAtRet && instr.FlowControl == FlowControl.Return) break;
        }
        return new { bitness, imageBase = "0x" + imageBase.ToString("X"), instructions };
    }

    private static object ReadBytes(JsonElement args)
    {
        string path = RequirePath(args);
        if (!TryParseNumber(args.GetProperty("offset"), out long offset))
            return new { error = "Couldn't parse 'offset'." };
        int length = args.TryGetProperty("length", out var le) && le.TryGetInt32(out int l)
            ? Math.Clamp(l, 1, 65536) : 256;

        var bytes = System.IO.File.ReadAllBytes(path);
        if (offset < 0 || offset >= bytes.Length)
            return new { error = $"Offset 0x{offset:X} out of range (size {bytes.Length})." };
        int take = (int)Math.Min(length, bytes.Length - offset);
        var slice = new byte[take];
        Array.Copy(bytes, offset, slice, 0, take);

        var sb = new StringBuilder();
        for (int row = 0; row < slice.Length; row += 16)
        {
            sb.Append((offset + row).ToString("X8")).Append("  ");
            int end = Math.Min(row + 16, slice.Length);
            for (int i = row; i < row + 16; i++)
            {
                if (i < end) sb.Append(slice[i].ToString("X2"));
                else sb.Append("  ");
                sb.Append(' ');
                if (i == row + 7) sb.Append(' ');
            }
            sb.Append(' ');
            for (int i = row; i < end; i++)
            {
                byte b = slice[i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return new
        {
            offsetHex = "0x" + offset.ToString("X"),
            length = take,
            hexDump = sb.ToString(),
            base64 = Convert.ToBase64String(slice),
        };
    }

    private static string RequirePath(JsonElement args)
    {
        if (!args.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String)
            throw new ArgumentException("Missing required 'path' string argument.");
        string path = p.GetString() ?? "";
        if (!System.IO.File.Exists(path))
            throw new FileNotFoundException($"File not found: {path}");
        return path;
    }

    private static bool TryParseNumber(JsonElement el, out long value)
    {
        value = 0;
        if (el.ValueKind == JsonValueKind.Number) { value = el.GetInt64(); return true; }
        if (el.ValueKind != JsonValueKind.String) return false;
        string s = el.GetString()?.Trim() ?? "";
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(s.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out value);
        return long.TryParse(s, out value);
    }
}
