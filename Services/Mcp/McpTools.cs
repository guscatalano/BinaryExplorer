using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using BinaryExplorer.Analysis;
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
        new
        {
            name = "list_imports",
            description = "Return the PE's static import table grouped by DLL, with named functions and ordinal imports.",
            inputSchema = StringPathOnly("Filesystem path to a Windows PE binary."),
        },
        new
        {
            name = "list_exports",
            description = "Return the PE's named exports with their RVAs.",
            inputSchema = StringPathOnly("Filesystem path to a Windows PE binary."),
        },
        new
        {
            name = "find_function_starts",
            description = "Run the whole-binary analyzer and return every detected function (confirmed=entry/exports/TLS, discovered=call targets) with RVA + section.",
            inputSchema = StringPathOnly("Filesystem path to a Windows PE binary."),
        },
        new
        {
            name = "search_bytes",
            description = "Find a byte pattern anywhere in the file. Pattern accepts hex with optional spaces ('4D 5A 90 00' or '4D5A9000') or a quoted ASCII string (\"MZ\"). Returns file offsets.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    pattern = new { type = "string", description = "Hex bytes or ASCII string. Wildcards not supported in v1." },
                    max = new { type = "integer", description = "Max matches to return. Default 1000.", minimum = 1, maximum = 100000 },
                },
                required = new[] { "path", "pattern" },
            },
        },
        new
        {
            name = "find_string_refs",
            description = "Locate occurrences of an ASCII/UTF-16LE string in the binary, and return raw-byte references to each occurrence's VA elsewhere in the file (helps find code that points at the string).",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    @string = new { type = "string", description = "The string to look for." },
                },
                required = new[] { "path", "string" },
            },
        },
        new
        {
            name = "extract_embedded",
            description = "Extract a slice of the binary to a temp file. If 'size' is omitted, the size is auto-detected via the same logic the Embedded Files inspector uses; if that fails, defaults to min(EOF-offset, 32MB). Returns the temp file path so you can re-inspect the dropped blob.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    offset = new { type = "string", description = "Starting file offset (0x... or decimal)." },
                    size = new { type = "string", description = "Optional explicit byte count." },
                    extension = new { type = "string", description = "Optional file extension for the temp file (e.g. '.zip', '.cab', '.exe')." },
                },
                required = new[] { "path", "offset" },
            },
        },
        new
        {
            name = "list_cab_files",
            description = "Parse a Microsoft Cabinet (.cab) archive header and return its file table with names, sizes, dates, and folder indexes.",
            inputSchema = StringPathOnly("Filesystem path to a .cab archive or to a file with a CAB header starting at offset 0."),
        },
        new
        {
            name = "query_msi_table",
            description = "Open a Windows Installer .msi database read-only and return every row of one table (e.g. File, Registry, Shortcut, Property, Feature, Component, Directory, CustomAction, LaunchCondition). Uses the local Windows Installer API via COM.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string", description = "Filesystem path to an .msi (or .msm) database." },
                    table = new { type = "string", description = "MSI table name." },
                },
                required = new[] { "path", "table" },
            },
        },
        new
        {
            name = "summarize_msi",
            description = "Open a Windows Installer .msi and return a structured summary: product info (ProductName, ProductCode, ProductVersion, Manufacturer, UpgradeCode), files dropped, registry writes, shortcuts created, custom actions, features. The single-call equivalent of 'inspect' for installers.",
            inputSchema = StringPathOnly("Filesystem path to an .msi database."),
        },
        new
        {
            name = "dump_section",
            description = "Write a PE section's raw bytes to a temp file. Useful for piping a section to an external tool or for further inspection.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    section = new { type = "string", description = "Section name (e.g. '.text', '.rsrc') or 0-based index." },
                },
                required = new[] { "path", "section" },
            },
        },
        new
        {
            name = "extract_resource",
            description = "Extract a single PE resource entry to a temp file. The matched resource is written verbatim (e.g. the embedded driver in procmon64.exe's RT_RCDATA can be extracted and then inspected with 'inspect').",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    resourceType = new
                    {
                        type = "string",
                        description = "Win32 resource type name (e.g. 'RT_RCDATA', 'RT_BITMAP'), numeric id (e.g. '10'), or a custom string type (e.g. 'WEVT_TEMPLATE').",
                    },
                    resourceName = new
                    {
                        type = "string",
                        description = "Optional. Resource name (string) or '#N' for a numeric id. When omitted, the first matching entry is written.",
                    },
                },
                required = new[] { "path", "resourceType" },
            },
        },
    };

    public static async Task<McpJsonRpcResponse> CallAsync(object? id, string name, JsonElement args)
    {
        try
        {
            object? payload = name switch
            {
                "list_inspectors"      => new { inspectors = BinaryLoader.DefaultInspectors.Select(i => i.Name).ToArray() },
                "inspect"              => await InspectAsync(args),
                "disassemble"          => await Task.Run(() => Disassemble(args)),
                "read_bytes"           => await Task.Run(() => ReadBytes(args)),
                "list_imports"         => await Task.Run(() => ListImports(args)),
                "list_exports"         => await Task.Run(() => ListExports(args)),
                "find_function_starts" => await Task.Run(() => FindFunctionStarts(args)),
                "search_bytes"         => await Task.Run(() => SearchBytes(args)),
                "find_string_refs"     => await Task.Run(() => FindStringRefs(args)),
                "extract_embedded"     => await ExtractEmbedded(args),
                "list_cab_files"       => await Task.Run(() => ListCabFiles(args)),
                "query_msi_table"      => await Task.Run(() => QueryMsiTable(args)),
                "summarize_msi"        => await Task.Run(() => SummarizeMsi(args)),
                "dump_section"         => await Task.Run(() => DumpSection(args)),
                "extract_resource"     => await Task.Run(() => ExtractResource(args)),
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

    // ===================== inspect =====================

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
                    f.Title, f.Value, f.Details, severity = f.Severity.ToString(),
                }).ToArray(),
            };
        }

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
                findings = r.Findings.Take(PreviewCap).Select(f => new { f.Title, f.Value, severity = f.Severity.ToString() }).ToArray(),
                truncated = r.Findings.Count > PreviewCap,
            }).ToArray(),
        };
    }

    // ===================== disassemble =====================

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

    // ===================== read_bytes =====================

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
                if (i < end) sb.Append(slice[i].ToString("X2")); else sb.Append("  ");
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

    // ===================== list_imports / list_exports =====================

    private static object ListImports(JsonElement args)
    {
        string path = RequirePath(args);
        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var dlls = PeImports.Read(pe, out _);
        return new
        {
            path = ctx.Path,
            dllCount = dlls.Count,
            imports = dlls.Select(d => new
            {
                dll = d.Dll,
                functions = d.Functions,
                ordinals = d.Ordinals,
            }).ToArray(),
        };
    }

    private static object ListExports(JsonElement args)
    {
        string path = RequirePath(args);
        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var exports = InterfacesInspector.ReadExports(ctx.Bytes, pe);
        return new
        {
            path = ctx.Path,
            count = exports.Count,
            exports = exports.Select(e => new { name = e.Name, rva = "0x" + e.Rva.ToString("X") }).ToArray(),
        };
    }

    // ===================== find_function_starts =====================

    private static object FindFunctionStarts(JsonElement args)
    {
        string path = RequirePath(args);
        var ctx = new BinaryContext(path);
        var idx = PeAnalysis.Analyze(ctx);
        if (!idx.Supported)
            return new { error = "Unsupported machine architecture (x86/x64 only)." };
        return new
        {
            path = ctx.Path,
            bitness = idx.Bitness,
            imageBase = "0x" + idx.ImageBase.ToString("X"),
            functionCount = idx.Functions.Count,
            functions = idx.Functions.Select(f => new
            {
                name = f.Name,
                rva = "0x" + f.Rva.ToString("X"),
                confirmed = f.Confirmed,
                section = f.Section,
            }).ToArray(),
        };
    }

    // ===================== search_bytes =====================

    private static object SearchBytes(JsonElement args)
    {
        string path = RequirePath(args);
        string pattern = args.TryGetProperty("pattern", out var pe) && pe.ValueKind == JsonValueKind.String
            ? pe.GetString() ?? "" : "";
        int max = args.TryGetProperty("max", out var me) && me.TryGetInt32(out int m)
            ? Math.Clamp(m, 1, 100000) : 1000;
        if (string.IsNullOrEmpty(pattern))
            return new { error = "Missing 'pattern' argument." };

        byte[]? needle = TryParsePattern(pattern);
        if (needle is null || needle.Length == 0)
            return new { error = $"Couldn't parse pattern: '{pattern}'." };

        var bytes = System.IO.File.ReadAllBytes(path);
        var hits = new List<long>();
        var span = (ReadOnlySpan<byte>)bytes;
        var nspan = (ReadOnlySpan<byte>)needle;

        int from = 0;
        while (hits.Count < max && from <= span.Length - nspan.Length)
        {
            int idx = span.Slice(from).IndexOf(nspan);
            if (idx < 0) break;
            hits.Add(from + idx);
            from = from + idx + 1;
        }

        return new
        {
            path,
            patternLength = needle.Length,
            matchCount = hits.Count,
            truncated = hits.Count >= max,
            offsets = hits.Select(o => "0x" + o.ToString("X")).ToArray(),
        };
    }

    private static byte[]? TryParsePattern(string s)
    {
        s = s.Trim();
        if (s.StartsWith("\"") && s.EndsWith("\"") && s.Length >= 2)
            return Encoding.ASCII.GetBytes(s.Substring(1, s.Length - 2));
        // Hex with optional spaces.
        var hex = new StringBuilder(s.Length);
        foreach (var c in s) if (!char.IsWhiteSpace(c)) hex.Append(c);
        if (hex.Length == 0 || hex.Length % 2 != 0) return null;
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(hex.ToString().AsSpan(i * 2, 2),
                System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                return null;
        }
        return bytes;
    }

    // ===================== find_string_refs =====================

    private static object FindStringRefs(JsonElement args)
    {
        string path = RequirePath(args);
        string s = args.TryGetProperty("string", out var se) && se.ValueKind == JsonValueKind.String
            ? se.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(s)) return new { error = "Missing 'string' argument." };

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        ulong imageBase = opt?.ImageBase ?? 0;
        bool pe32Plus = opt?.Magic == PEMagic.PE32Plus;
        int ptrSize = pe32Plus ? 8 : 4;

        var asciiBytes = Encoding.ASCII.GetBytes(s);
        var wideBytes = Encoding.Unicode.GetBytes(s);

        var stringLocations = new List<(long FileOffset, string Encoding)>();
        var span = (ReadOnlySpan<byte>)ctx.Bytes;
        FindAll(span, asciiBytes, "ASCII", stringLocations);
        FindAll(span, wideBytes, "UTF-16LE", stringLocations);

        // For each found location, compute its VA via RVA->file mapping in reverse.
        var refs = new List<object>();
        if (opt is not null)
        {
            foreach (var (fileOff, enc) in stringLocations)
            {
                long? rva = FileOffsetToRva(pe, (int)fileOff);
                if (rva is null) continue;
                ulong va = imageBase + (ulong)rva.Value;
                var vaBytes = pe32Plus
                    ? BitConverter.GetBytes((ulong)va)
                    : BitConverter.GetBytes((uint)va);
                int from = 0;
                int matchCount = 0;
                while (matchCount < 200 && from <= span.Length - vaBytes.Length)
                {
                    int idx = span.Slice(from).IndexOf((ReadOnlySpan<byte>)vaBytes);
                    if (idx < 0) break;
                    int hitOff = from + idx;
                    if (hitOff != (int)fileOff)
                    {
                        long? hitRva = FileOffsetToRva(pe, hitOff);
                        refs.Add(new
                        {
                            referencedStringFileOffset = "0x" + fileOff.ToString("X"),
                            referencedStringEncoding = enc,
                            referencedStringVa = "0x" + va.ToString("X"),
                            refFileOffset = "0x" + hitOff.ToString("X"),
                            refRva = hitRva is long r ? "0x" + r.ToString("X") : null,
                        });
                        matchCount++;
                    }
                    from = hitOff + 1;
                }
            }
        }

        return new
        {
            path,
            stringHits = stringLocations.Select(l => new
            {
                fileOffset = "0x" + l.FileOffset.ToString("X"),
                encoding = l.Encoding,
            }).ToArray(),
            references = refs,
        };
    }

    private static void FindAll(ReadOnlySpan<byte> haystack, byte[] needle, string label, List<(long, string)> sink)
    {
        if (needle.Length == 0) return;
        int from = 0;
        while (from <= haystack.Length - needle.Length)
        {
            int idx = haystack.Slice(from).IndexOf((ReadOnlySpan<byte>)needle);
            if (idx < 0) break;
            sink.Add((from + idx, label));
            from = from + idx + 1;
        }
    }

    private static long? FileOffsetToRva(PEReader pe, int fileOffset)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            if (fileOffset >= s.PointerToRawData && fileOffset < s.PointerToRawData + s.SizeOfRawData)
                return (long)(s.VirtualAddress + (fileOffset - s.PointerToRawData));
        }
        return null;
    }

    // ===================== extract_embedded =====================

    private static async Task<object> ExtractEmbedded(JsonElement args)
    {
        string path = RequirePath(args);
        if (!TryParseNumber(args.GetProperty("offset"), out long offset))
            return new { error = "Couldn't parse 'offset'." };

        long? explicitSize = null;
        if (args.TryGetProperty("size", out var se) && TryParseNumber(se, out long explicitS))
            explicitSize = explicitS;
        string? extOverride = args.TryGetProperty("extension", out var xe) && xe.ValueKind == JsonValueKind.String
            ? xe.GetString() : null;

        var ctx = new BinaryContext(path);
        if (offset < 0 || offset >= ctx.Bytes.LongLength)
            return new { error = $"Offset 0x{offset:X} out of range (size {ctx.Bytes.LongLength})." };

        // Try to find a matching EmbeddedHit for size auto-detect.
        EmbeddedHit? matched = null;
        if (explicitSize is null)
        {
            var emb = new EmbeddedFilesInspector();
            var res = await emb.InspectAsync(ctx).ConfigureAwait(false);
            if (res.Payload is IEnumerable<EmbeddedHit> hits)
                matched = hits.FirstOrDefault(h => h.Offset == offset);
        }

        long size = explicitSize
            ?? matched?.Size
            ?? Math.Min(ctx.Bytes.LongLength - offset, 32L * 1024 * 1024);

        string ext = extOverride ?? matched?.SuggestedExtension ?? ".bin";
        string typeLabel = matched?.Type ?? "blob";
        string stem = System.IO.Path.GetFileNameWithoutExtension(path);
        string fileName = $"{stem}_+{offset:X8}_{Sanitize(typeLabel)}{ext}";
        string outDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "BinaryExplorer");
        System.IO.Directory.CreateDirectory(outDir);
        string outPath = System.IO.Path.Combine(outDir, fileName);

        await using (var fs = new System.IO.FileStream(outPath, System.IO.FileMode.Create, System.IO.FileAccess.Write))
            await fs.WriteAsync(ctx.Bytes.AsMemory((int)offset, (int)size)).ConfigureAwait(false);

        return new
        {
            path = outPath,
            offsetHex = "0x" + offset.ToString("X"),
            size,
            detectedType = matched?.Type,
            sizeAutoDetected = matched is not null && explicitSize is null,
        };
    }

    private static string Sanitize(string s)
    {
        var invalid = System.IO.Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(Array.IndexOf(invalid, c) >= 0 || c == ' ' || c == '/' ? '_' : c);
        return sb.ToString();
    }

    // ===================== list_cab_files =====================

    private static object ListCabFiles(JsonElement args)
    {
        string path = RequirePath(args);
        var bytes = System.IO.File.ReadAllBytes(path);
        return ParseCabHeader(bytes, 0);
    }

    /// <summary>
    /// CAB header layout per [MS-CAB]. Returns a structured representation or { error }.
    /// </summary>
    private static object ParseCabHeader(byte[] bytes, int baseOffset)
    {
        if (baseOffset + 36 > bytes.Length) return new { error = "Not enough bytes for CAB header." };
        if (!(bytes[baseOffset] == 'M' && bytes[baseOffset + 1] == 'S'
            && bytes[baseOffset + 2] == 'C' && bytes[baseOffset + 3] == 'F'))
            return new { error = "Missing 'MSCF' signature at offset 0." };

        uint cbCabinet = BitConverter.ToUInt32(bytes, baseOffset + 8);
        uint coffFiles = BitConverter.ToUInt32(bytes, baseOffset + 16);
        ushort cFolders = BitConverter.ToUInt16(bytes, baseOffset + 26);
        ushort cFiles = BitConverter.ToUInt16(bytes, baseOffset + 28);
        ushort flags = BitConverter.ToUInt16(bytes, baseOffset + 30);

        int p = baseOffset + (int)coffFiles;
        var files = new List<object>();
        for (int i = 0; i < cFiles && p + 16 < bytes.Length; i++)
        {
            uint cbFile = BitConverter.ToUInt32(bytes, p);
            uint uoffFolderStart = BitConverter.ToUInt32(bytes, p + 4);
            ushort iFolder = BitConverter.ToUInt16(bytes, p + 8);
            ushort date = BitConverter.ToUInt16(bytes, p + 10);
            ushort time = BitConverter.ToUInt16(bytes, p + 12);
            ushort attribs = BitConverter.ToUInt16(bytes, p + 14);
            int nameStart = p + 16;
            int nameEnd = nameStart;
            // CAB filenames are typically ASCII; UTF-8 when attribs & 0x80 (cffileNAME_IS_UTF).
            while (nameEnd < bytes.Length && bytes[nameEnd] != 0) nameEnd++;
            if (nameEnd >= bytes.Length) break;
            string name = (attribs & 0x80) != 0
                ? Encoding.UTF8.GetString(bytes, nameStart, nameEnd - nameStart)
                : Encoding.ASCII.GetString(bytes, nameStart, nameEnd - nameStart);
            files.Add(new
            {
                name,
                size = cbFile,
                folderIndex = iFolder,
                offsetInFolder = "0x" + uoffFolderStart.ToString("X"),
                attribs = "0x" + attribs.ToString("X"),
                date = DecodeCabDate(date, time),
            });
            p = nameEnd + 1;
        }

        return new
        {
            cabinetSize = cbCabinet,
            folders = cFolders,
            files = cFiles,
            flags = "0x" + flags.ToString("X"),
            firstFileOffset = "0x" + coffFiles.ToString("X"),
            entries = files,
        };
    }

    private static string DecodeCabDate(ushort date, ushort time)
    {
        try
        {
            int y = ((date >> 9) & 0x7F) + 1980;
            int m = (date >> 5) & 0x0F;
            int d = date & 0x1F;
            int h = (time >> 11) & 0x1F;
            int mi = (time >> 5) & 0x3F;
            int s = (time & 0x1F) * 2;
            return new DateTime(y, m == 0 ? 1 : m, d == 0 ? 1 : d, h, mi, s).ToString("u");
        }
        catch { return "?"; }
    }

    // ===================== query_msi_table / summarize_msi =====================

    private static object DumpSection(JsonElement args)
    {
        string path = RequirePath(args);
        string sectionArg = args.TryGetProperty("section", out var se) && se.ValueKind == JsonValueKind.String
            ? se.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(sectionArg)) return new { error = "Missing 'section' argument." };

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var headers = pe.PEHeaders.SectionHeaders;

        int targetIndex = -1;
        if (int.TryParse(sectionArg, out var byIndex) && byIndex >= 0 && byIndex < headers.Length)
        {
            targetIndex = byIndex;
        }
        else
        {
            for (int i = 0; i < headers.Length; i++)
            {
                if (string.Equals(headers[i].Name, sectionArg, StringComparison.Ordinal)) { targetIndex = i; break; }
            }
        }
        if (targetIndex < 0)
        {
            return new
            {
                error = $"Section '{sectionArg}' not found.",
                available = headers.Select(h => h.Name).ToArray(),
            };
        }
        var s = headers[targetIndex];
        int off = s.PointerToRawData;
        int size = s.SizeOfRawData;
        if (off < 0 || size <= 0 || off + size > ctx.Bytes.Length)
            return new { error = $"Section '{s.Name}' bytes are outside the file." };

        var slice = new byte[size];
        Array.Copy(ctx.Bytes, off, slice, 0, size);

        string outDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "BinaryExplorer");
        System.IO.Directory.CreateDirectory(outDir);
        string fileName = $"{System.IO.Path.GetFileNameWithoutExtension(path)}_{Sanitize(s.Name)}.bin";
        string outPath = System.IO.Path.Combine(outDir, fileName);
        System.IO.File.WriteAllBytes(outPath, slice);

        var sha = System.Security.Cryptography.SHA256.HashData(slice);
        return new
        {
            sectionName = s.Name,
            sectionIndex = targetIndex,
            fileOffset = "0x" + off.ToString("X"),
            virtualAddress = "0x" + s.VirtualAddress.ToString("X"),
            rawSize = size,
            outputPath = outPath,
            sha256 = Convert.ToHexString(sha).ToLowerInvariant(),
        };
    }

    private static object ExtractResource(JsonElement args)
    {
        string path = RequirePath(args);
        string typeArg = args.TryGetProperty("resourceType", out var tre) && tre.ValueKind == JsonValueKind.String
            ? tre.GetString() ?? "" : "";
        string? nameArg = args.TryGetProperty("resourceName", out var nre) && nre.ValueKind == JsonValueKind.String
            ? nre.GetString() : null;
        if (string.IsNullOrEmpty(typeArg)) return new { error = "Missing 'resourceType' argument." };

        var bytes = System.IO.File.ReadAllBytes(path);
        var entries = PeResources.Walk(bytes);
        if (entries.Count == 0) return new { error = "No resource directory in this PE." };

        bool TypeMatches(ResourceEntry e) =>
            // Numeric id: "10"
            (int.TryParse(typeArg, out var n) && e.TypeId == n) ||
            // RT_RCDATA / RT_MANIFEST: TypeDisplay holds the canonical name
            string.Equals(e.TypeDisplay, typeArg, StringComparison.OrdinalIgnoreCase) ||
            // Custom string types: e.g. "WEVT_TEMPLATE"
            string.Equals(e.TypeString, typeArg, StringComparison.OrdinalIgnoreCase);

        bool NameMatches(ResourceEntry e)
        {
            if (nameArg is null) return true;
            string trimmed = nameArg.TrimStart('#');
            return string.Equals(e.NameDisplay, nameArg, StringComparison.OrdinalIgnoreCase)
                || string.Equals(e.NameDisplay.TrimStart('#'), trimmed, StringComparison.OrdinalIgnoreCase)
                || string.Equals(e.NameString, nameArg, StringComparison.OrdinalIgnoreCase);
        }

        var matches = entries.Where(e => TypeMatches(e) && NameMatches(e)).ToList();
        if (matches.Count == 0)
        {
            return new
            {
                error = $"No resource matched type='{typeArg}' name='{nameArg ?? "(any)"}'.",
                availableTypes = entries.Select(e => e.TypeDisplay).Distinct().OrderBy(s => s).ToArray(),
            };
        }

        var entry = matches[0];
        if (entry.FileOffset < 0 || entry.Size <= 0 || entry.FileOffset + entry.Size > bytes.Length)
            return new { error = "Resource bytes are outside the file." };

        var slice = new byte[entry.Size];
        Array.Copy(bytes, entry.FileOffset, slice, 0, entry.Size);

        string detectedType = DetectInnerFormat(slice);
        string outDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "BinaryExplorer");
        System.IO.Directory.CreateDirectory(outDir);
        string fileName = $"{System.IO.Path.GetFileNameWithoutExtension(path)}_{Sanitize(entry.TypeDisplay)}_{Sanitize(entry.NameDisplay.TrimStart('#'))}.bin";
        string outPath = System.IO.Path.Combine(outDir, fileName);
        System.IO.File.WriteAllBytes(outPath, slice);

        var sha = System.Security.Cryptography.SHA256.HashData(slice);
        return new
        {
            outputPath = outPath,
            sizeBytes = slice.Length,
            detectedType,
            sha256 = Convert.ToHexString(sha).ToLowerInvariant(),
            resource = new
            {
                type = entry.TypeDisplay,
                name = entry.NameDisplay,
                language = "0x" + entry.Language.ToString("X4"),
                fileOffset = "0x" + entry.FileOffset.ToString("X"),
            },
            candidatesConsidered = matches.Count,
        };
    }

    private static string DetectInnerFormat(byte[] b)
    {
        if (b.Length >= 2 && b[0] == 0x4D && b[1] == 0x5A) return "PE/DOS (MZ header)";
        if (b.Length >= 4 && b[0] == 0x4D && b[1] == 0x53 && b[2] == 0x43 && b[3] == 0x46) return "CAB";
        if (b.Length >= 4 && b[0] == 0x50 && b[1] == 0x4B && b[2] == 0x03 && b[3] == 0x04) return "ZIP";
        if (b.Length >= 8 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47) return "PNG";
        if (b.Length >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "JPEG";
        if (b.Length >= 4 && b[0] == 0x25 && b[1] == 0x50 && b[2] == 0x44 && b[3] == 0x46) return "PDF";
        if (b.Length >= 6 && b[0] == 0x37 && b[1] == 0x7A && b[2] == 0xBC && b[3] == 0xAF && b[4] == 0x27 && b[5] == 0x1C) return "7-Zip";
        if (b.Length >= 5 && b[0] == 0x3C && b[1] == 0x3F && b[2] == 0x78 && b[3] == 0x6D && b[4] == 0x6C) return "XML";
        return "binary";
    }

    private static object QueryMsiTable(JsonElement args)
    {
        string path = RequirePath(args);
        string table = args.TryGetProperty("table", out var te) && te.ValueKind == JsonValueKind.String
            ? te.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(table))
            return new { error = "Missing 'table' argument." };
        return MsiQuery.Query(path, table);
    }

    private static object SummarizeMsi(JsonElement args)
    {
        string path = RequirePath(args);
        return MsiQuery.Summarize(path);
    }

    // ===================== helpers =====================

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

    private static object StringPathOnly(string desc) => new
    {
        type = "object",
        properties = new
        {
            path = new { type = "string", description = desc },
        },
        required = new[] { "path" },
    };
}
