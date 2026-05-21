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
                required = Array.Empty<string>(),
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
            name = "set_current_target",
            description = "Set a process-wide 'current target' binary. Once set, every other tool can be called without a 'path' argument and operates on this file. An explicit 'path' on any call still overrides it. Ideal for interactive sessions inspecting one binary repeatedly.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string", description = "Filesystem path to the binary to make current." },
                },
                required = new[] { "path" },
            },
        },
        new
        {
            name = "get_current_target",
            description = "Report target resolution: the MCP session target (set via set_current_target), the file currently open in the BinaryExplorer UI, and which one tools will use when 'path' is omitted.",
            inputSchema = new { type = "object", properties = new { } },
        },
        new
        {
            name = "clear_current_target",
            description = "Clear the MCP session target. Tools then fall back to the file open in the BinaryExplorer UI, or require an explicit 'path'.",
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
                required = new[] { "rva" },
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
                required = new[] { "offset" },
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
                required = new[] { "pattern" },
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
                required = new[] { "string" },
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
                required = new[] { "offset" },
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
                required = new[] { "table" },
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
                required = new[] { "section" },
            },
        },
        new
        {
            name = "resolve_guid",
            description = "Look up a GUID in the local Windows registry: HKLM/HKCU and WOW6432Node mirrors of Classes\\CLSID, Interface, AppID, TypeLib. Returns category (CLSID/IID/AppID/TypeLib), friendly name, ProgID, InprocServer/LocalServer paths if registered. Useful for identifying which embedded GUIDs in a binary are actually registered COM classes.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    guid = new { type = "string", description = "Single GUID, with or without braces." },
                    guids = new
                    {
                        type = "array",
                        items = new { type = "string" },
                        description = "Optional list of GUIDs to resolve in a single call.",
                    },
                },
            },
        },
        new
        {
            name = "get_string_at",
            description = "Read a null-terminated string at a file offset. With encoding='auto' (default), decodes as UTF-16LE if the second byte is 0x00 and the first looks printable, otherwise ASCII. Returns the value, encoding chosen, and byte length.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    offset = new { type = "string", description = "File offset (0x... or decimal)." },
                    encoding = new { type = "string", description = "'auto' (default), 'ascii', or 'utf-16le'." },
                    maxLength = new { type = "integer", description = "Max characters to read (default 1024, max 8192).", minimum = 1, maximum = 8192 },
                },
                required = new[] { "offset" },
            },
        },
        new
        {
            name = "find_xrefs",
            description = "Find every instruction that references a given VA/RVA. Walks every executable section with Iced, checking branch targets, RIP-relative memory operands, and immediate operands. Pass a VA (0x140012345) or an RVA (0x12345) — both work.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    target = new { type = "string", description = "Target address. Hex 0x... or decimal. < imageBase is treated as an RVA." },
                    max = new { type = "integer", description = "Cap on number of references returned. Default 500.", minimum = 1, maximum = 10000 },
                },
                required = new[] { "target" },
            },
        },
        new
        {
            name = "get_pe_map",
            description = "Block diagram of a PE's structure: sections (with size + characteristics) on the left, imported DLLs in the middle, embedded resources / detected blobs on the right. Default format: 'mermaid'.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    format = new { type = "string", description = "'mermaid' (default) or 'json'." },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "get_call_graph",
            description = "Walk calls from a starting RVA up to N levels deep. Returns a Mermaid flowchart with one node per discovered function and edges for each direct call. Indirect calls (call qword ptr [iat]) are resolved against the import address table and shown as 'dll!function' nodes.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    rva = new { type = "string", description = "Starting RVA (hex 0x... or decimal). If omitted, uses the PE entry point." },
                    depth = new { type = "integer", description = "BFS depth from the start. Default 2, max 5.", minimum = 1, maximum = 5 },
                    format = new { type = "string", description = "'mermaid' (default) or 'json'." },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "get_init_sequence",
            description = "Mermaid sequence diagram of the init chain. Starts at the PE entry point (or the supplied RVA) and follows the first call at each level until it hits an import or runs out of depth.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    rva = new { type = "string", description = "Optional starting RVA; defaults to the PE entry point." },
                    depth = new { type = "integer", description = "Max levels of nesting. Default 8.", minimum = 1, maximum = 32 },
                    format = new { type = "string", description = "'mermaid' (default) or 'json'." },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "architecture_evidence_pack",
            description = "Evidence-only structured pack: sections, imports (with thunk-collapsed callsite usage), control-flow (function starts, callGraphSummary, entryReachable BFS, teardownCandidates), strings (StringsInspector passthrough), per-function feature vectors, and all inspector findings (raw + normalized). Every derived field carries a deterministic rule ID under provenance.fieldSources. No narrative or semantic labels — pure aggregation. teardownCandidates scores functions purely on the count of distinct teardown-flavored imports they call (no init/unload classification claimed).",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    scope = new
                    {
                        type = "object",
                        properties = new
                        {
                            maxFunctions = new { type = "integer", description = "Default 2000.", minimum = 1, maximum = 50000 },
                            maxEdges = new { type = "integer", description = "Default 10000.", minimum = 1, maximum = 200000 },
                            includeStrings = new { type = "boolean", description = "Default true." },
                            includeImports = new { type = "boolean", description = "Default true." },
                            includeSections = new { type = "boolean", description = "Default true." },
                            entryRva = new { type = "string", description = "Override start RVA (defaults to PE entry point)." },
                            timeoutMs = new { type = "integer", description = "Soft bound for total work. Default 30000." },
                        },
                    },
                    options = new
                    {
                        type = "object",
                        properties = new
                        {
                            resolveThunks = new { type = "boolean", description = "Default true. Maps to thunk-collapse-v1 rule." },
                            inferInitTeardownCandidates = new { type = "boolean", description = "v1 — currently a no-op in v0; always returns []." },
                            includePerFunctionFeatures = new { type = "boolean", description = "v2 — currently a no-op in v0; always returns []." },
                            includeInspectorFindings = new { type = "boolean", description = "Default true." },
                            includeRawRefsSample = new { type = "boolean", description = "Reserved." },
                        },
                    },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "summarize_import_usage",
            description = "For each imported function, list every callsite (with enclosing function RVA + section) and call site count. resolveThunks (default true) folds 'call thunk' callsites into the import the thunk wraps so a single call site isn't reported twice. Filter with includeDllFilter[] / includeFunctionFilter[] (case-insensitive). No phase inference — phases are not derivable from static analysis with the confidence to label them.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    includeDllFilter = new { type = "array", items = new { type = "string" }, description = "Optional case-insensitive DLL name allow-list (no .dll suffix)." },
                    includeFunctionFilter = new { type = "array", items = new { type = "string" }, description = "Optional case-insensitive function name allow-list." },
                    resolveThunks = new { type = "boolean", description = "Default true." },
                    maxCallsitesPerImport = new { type = "integer", description = "Cap per import. Default 200.", minimum = 1, maximum = 100000 },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "find_string_refs_ex",
            description = "Locate ASCII/UTF-16LE occurrences of a string and nest each hit's code references underneath it. Each hit reports VA/RVA/section in addition to fileOffset, so callers don't have to re-correlate.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    query = new { type = "string", description = "The string to look for." },
                    encoding = new { type = "string", description = "'auto' (default), 'ascii', or 'utf-16le'." },
                    resolveCodeRefs = new { type = "boolean", description = "When true, scan the file for raw-byte references to each hit's VA. Default true." },
                    maxHits = new { type = "integer", description = "Cap on string occurrences. Default 1000.", minimum = 1, maximum = 100000 },
                    maxRefsPerHit = new { type = "integer", description = "Cap on code refs per hit. Default 200.", minimum = 0, maximum = 10000 },
                },
                required = new[] { "query" },
            },
        },
        new
        {
            name = "get_call_graph_ex",
            description = "Call-graph BFS with explicit branch controls. Knobs: resolveThunks (collapse call→thunk→import into one import edge, default true), includeTailCalls (jmp leaving the enclosing function counts as a call, default true), followConditionalBranches (Jcc edges, default false — explodes graph size), pruneImports (omit import leaves, default false), maxNodes/maxEdges caps with truncated flag. format = 'json' (default) or 'mermaid'.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    address = new
                    {
                        type = "object",
                        properties = new
                        {
                            va = new { type = "string" },
                            rva = new { type = "string" },
                            fileOffset = new { type = "string" },
                        },
                    },
                    rva = new { type = "string", description = "Back-compat starting RVA (use 'address' for AddressRef)." },
                    depth = new { type = "integer", description = "BFS depth. Default 2, max 8.", minimum = 1, maximum = 8 },
                    followConditionalBranches = new { type = "boolean", description = "Default false." },
                    includeTailCalls = new { type = "boolean", description = "Default true." },
                    resolveThunks = new { type = "boolean", description = "Default true." },
                    includeImports = new { type = "boolean", description = "Default true." },
                    pruneImports = new { type = "boolean", description = "Default false." },
                    maxNodes = new { type = "integer", description = "Default 2000.", minimum = 1, maximum = 50000 },
                    maxEdges = new { type = "integer", description = "Default 10000.", minimum = 1, maximum = 200000 },
                    format = new { type = "string", description = "'json' (default) or 'mermaid'." },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "convert_address",
            description = "Convert between fileOffset, RVA, and VA, and identify the containing PE section. Accepts an AddressRef (object with va/rva/fileOffset; precedence: va > rva > fileOffset).",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    address = new
                    {
                        type = "object",
                        properties = new
                        {
                            va = new { type = "string", description = "Virtual address (0x... or decimal)." },
                            rva = new { type = "string", description = "Relative virtual address." },
                            fileOffset = new { type = "string", description = "Physical file offset." },
                        },
                    },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "disassemble_function",
            description = "Disassemble a whole function. Address is snapped backward to the nearest known function start; the body is decoded until a ret, the next known function start, or maxInstructions. Tailcalls (unconditional jmp leaving the function) end decoding unless followTailcalls is true.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    address = new
                    {
                        type = "object",
                        properties = new
                        {
                            va = new { type = "string" },
                            rva = new { type = "string" },
                            fileOffset = new { type = "string" },
                        },
                    },
                    followTailcalls = new { type = "boolean", description = "Continue decoding past unconditional inter-function jumps. Default false." },
                    includeImports = new { type = "boolean", description = "Annotate instructions whose memory operand targets an IAT slot. Default true." },
                    maxInstructions = new { type = "integer", description = "Cap on decoded instructions. Default 8000.", minimum = 1, maximum = 200000 },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "disassemble_nearest_function",
            description = "Find the nearest known function start to an address (within maxDistanceBytes) and disassemble from there. direction = 'nearest' (default), 'backward', or 'forward'.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    address = new
                    {
                        type = "object",
                        properties = new
                        {
                            va = new { type = "string" },
                            rva = new { type = "string" },
                            fileOffset = new { type = "string" },
                        },
                    },
                    direction = new { type = "string", description = "'nearest' (default), 'backward', or 'forward'." },
                    maxDistanceBytes = new { type = "integer", description = "Max bytes to search away. Default 4096.", minimum = 0, maximum = 16777216 },
                    maxInstructions = new { type = "integer", description = "Cap on decoded instructions. Default 1024.", minimum = 1, maximum = 200000 },
                },
                required = Array.Empty<string>(),
            },
        },
        new
        {
            name = "find_xrefs_ex",
            description = "Cross-references with enclosing-function grouping and thunk resolution. references[].fromFunctionStartRva is the start RVA of the function that contains the reference; references[].resolvedFinalTarget is set when the call target is a thunk that resolves to an import. AddressRef precedence: va > rva > fileOffset (top-level 'target' still accepted for back-compat).",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string" },
                    target = new { type = "string", description = "Back-compat target VA or RVA. Use 'address' instead for AddressRef." },
                    address = new
                    {
                        type = "object",
                        properties = new
                        {
                            va = new { type = "string" },
                            rva = new { type = "string" },
                            fileOffset = new { type = "string" },
                        },
                    },
                    resolveThunks = new { type = "boolean", description = "When the enclosing function is a thunk (first insn is jmp [iat]), annotate the resolved import. Default true." },
                    includeIndirectMemoryRefs = new { type = "boolean", description = "Default true." },
                    includeImmediateRefs = new { type = "boolean", description = "Default true." },
                    includeBranchRefs = new { type = "boolean", description = "Default true." },
                    groupByFunction = new { type = "boolean", description = "Include a 'groups' array bucketed by enclosing function RVA. Default true." },
                    max = new { type = "integer", description = "Cap on references returned. Default 2000.", minimum = 1, maximum = 100000 },
                },
                required = Array.Empty<string>(),
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
                required = new[] { "resourceType" },
            },
        },
    };

    public static async Task<McpJsonRpcResponse> CallAsync(object? id, string name, JsonElement args)
    {
        try
        {
            object? payload = await DispatchAsync(name, args).ConfigureAwait(false);
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

    /// <summary>
    /// UI-callable wrapper. Builds a JsonElement from the supplied object literal
    /// and routes to the same dispatch table as the HTTP server. Returns the raw
    /// payload object (the same anonymous record the MCP client would receive).
    /// </summary>
    public static async Task<object?> InvokeAsync(string toolName, object argsObject)
    {
        string json = JsonSerializer.Serialize(argsObject);
        var doc = JsonDocument.Parse(json);
        try
        {
            return await DispatchAsync(toolName, doc.RootElement).ConfigureAwait(false);
        }
        finally
        {
            doc.Dispose();
        }
    }

    private static async Task<object?> DispatchAsync(string name, JsonElement args)
    {
        return name switch
        {
            "list_inspectors"      => new { inspectors = BinaryLoader.DefaultInspectors.Select(i => i.Name).ToArray() },
            "set_current_target"   => SetCurrentTarget(args),
            "get_current_target"   => GetCurrentTarget(args),
            "clear_current_target" => ClearCurrentTarget(args),
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
            "resolve_guid"         => await Task.Run(() => ResolveGuid(args)),
            "get_string_at"        => await Task.Run(() => GetStringAt(args)),
            "find_xrefs"           => await Task.Run(() => FindXrefs(args)),
            "get_pe_map"           => await Task.Run(() => GetPeMap(args)),
            "get_call_graph"       => await Task.Run(() => GetCallGraph(args)),
            "get_init_sequence"    => await Task.Run(() => GetInitSequence(args)),
            "convert_address"          => await Task.Run(() => ConvertAddress(args)),
            "disassemble_function"     => await Task.Run(() => DisassembleFunction(args)),
            "disassemble_nearest_function" => await Task.Run(() => DisassembleNearestFunction(args)),
            "find_xrefs_ex"            => await Task.Run(() => FindXrefsEx(args)),
            "find_string_refs_ex"      => await Task.Run(() => FindStringRefsEx(args)),
            "get_call_graph_ex"        => await Task.Run(() => GetCallGraphEx(args)),
            "summarize_import_usage"   => await Task.Run(() => SummarizeImportUsage(args)),
            "architecture_evidence_pack" => await ArchitectureEvidencePack(args),
            _ => null,
        };
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

        bool pe32Plus = opt.Magic == PEMagic.PE32Plus;
        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);

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

            // IAT annotation: when the instruction touches a memory operand whose effective
            // address equals an IAT slot VA, surface the imported "dll!function" name.
            string? annotation = null;
            for (int i = 0; i < instr.OpCount; i++)
            {
                if (instr.GetOpKind(i) != OpKind.Memory) continue;
                ulong memAddr = instr.IsIPRelativeMemoryOperand
                    ? instr.IPRelativeMemoryAddress
                    : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                       ? (ulong)instr.MemoryDisplacement64
                       : 0UL);
                if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var name))
                {
                    annotation = name;
                    break;
                }
            }

            instructions.Add(new
            {
                ip = "0x" + ip.ToString("X16"),
                bytes = hex.ToString(),
                text = output.ToString(),
                importTarget = annotation,
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
        var opt = pe.PEHeaders.PEHeader;
        bool pe32Plus = opt?.Magic == PEMagic.PE32Plus;
        ulong imageBase = opt?.ImageBase ?? 0;

        var dlls = PeImports.Read(pe, out _);
        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);
        // Invert the IAT map (slot VA -> "dll!function") to "dll!function" -> slot VA so we
        // can look up each function's slot.
        var slotByFn = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var kv in iatMap) slotByFn[kv.Value] = kv.Key;

        return new
        {
            path = ctx.Path,
            imageBase = "0x" + imageBase.ToString("X"),
            dllCount = dlls.Count,
            imports = dlls.Select(d =>
            {
                string norm = d.Dll;
                foreach (var ext in new[] { ".dll", ".DLL" })
                    if (norm.EndsWith(ext)) { norm = norm[..^ext.Length]; break; }
                return new
                {
                    dll = d.Dll,
                    functions = d.Functions.Select(fn =>
                    {
                        string key = $"{norm}!{fn}";
                        slotByFn.TryGetValue(key, out var slotVa);
                        return new
                        {
                            name = fn,
                            iatSlotVa = slotVa == 0 ? null : "0x" + slotVa.ToString("X"),
                            iatSlotRva = slotVa == 0 ? null : "0x" + (slotVa - imageBase).ToString("X"),
                        };
                    }).ToArray(),
                    ordinals = d.Ordinals,
                };
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

    // ===================== AddressRef (shared parser) =====================

    /// <summary>
    /// Normalized address. Precedence when caller supplies more than one form: va > rva > fileOffset.
    /// </summary>
    private sealed record ResolvedAddress(
        ulong Va,
        uint Rva,
        int FileOffset,
        string? Section,
        bool Valid);

    /// <summary>
    /// Parse an AddressRef from either an "address" sub-object or inline va/rva/fileOffset fields.
    /// Returns null when no form is provided.
    /// </summary>
    private static ResolvedAddress? TryResolveAddress(JsonElement args, PEReader pe)
    {
        JsonElement addr = args;
        if (args.TryGetProperty("address", out var sub) && sub.ValueKind == JsonValueKind.Object)
            addr = sub;

        var opt = pe.PEHeaders.PEHeader;
        ulong imageBase = opt?.ImageBase ?? 0;

        // Precedence: va > rva > fileOffset.
        if (addr.TryGetProperty("va", out var vae) && TryParseNumber(vae, out long vaLong))
            return ResolveFromVa((ulong)vaLong, pe, imageBase);
        if (addr.TryGetProperty("rva", out var rvae) && TryParseNumber(rvae, out long rvaLong))
            return ResolveFromRva((uint)rvaLong, pe, imageBase);
        if (addr.TryGetProperty("fileOffset", out var foe) && TryParseNumber(foe, out long foLong))
            return ResolveFromFileOffset((int)foLong, pe, imageBase);

        // Back-compat with the simpler tools: if the caller passed `target` or `rva` at the top
        // level (the existing find_xrefs/disassemble shape), accept that too.
        if (args.TryGetProperty("target", out var tge) && TryParseNumber(tge, out long tgLong))
        {
            ulong va = (ulong)tgLong;
            if (va < imageBase) return ResolveFromRva((uint)tgLong, pe, imageBase);
            return ResolveFromVa(va, pe, imageBase);
        }
        if (args.TryGetProperty("rva", out var rva2) && TryParseNumber(rva2, out long rva2Long))
            return ResolveFromRva((uint)rva2Long, pe, imageBase);

        return null;
    }

    private static ResolvedAddress ResolveFromVa(ulong va, PEReader pe, ulong imageBase)
    {
        if (va < imageBase)
            return new ResolvedAddress(va, 0, -1, null, false);
        uint rva = (uint)(va - imageBase);
        return ResolveFromRva(rva, pe, imageBase, knownVa: va);
    }

    private static ResolvedAddress ResolveFromRva(uint rva, PEReader pe, ulong imageBase, ulong? knownVa = null)
    {
        ulong va = knownVa ?? (imageBase + rva);
        if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int fileOff))
            return new ResolvedAddress(va, rva, -1, null, false);
        string? section = FindSectionForRva(pe, rva);
        return new ResolvedAddress(va, rva, fileOff, section, true);
    }

    private static ResolvedAddress ResolveFromFileOffset(int fileOffset, PEReader pe, ulong imageBase)
    {
        long? rva = FileOffsetToRva(pe, fileOffset);
        if (rva is null)
            return new ResolvedAddress(0, 0, fileOffset, null, false);
        uint rvaU = (uint)rva.Value;
        ulong va = imageBase + rvaU;
        string? section = FindSectionForRva(pe, rvaU);
        return new ResolvedAddress(va, rvaU, fileOffset, section, true);
    }

    private static string? FindSectionForRva(PEReader pe, uint rva)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + (uint)s.VirtualSize)
                return s.Name;
        return null;
    }

    private static object FormatAddressRef(ResolvedAddress a) => new
    {
        va = "0x" + a.Va.ToString("X"),
        rva = "0x" + a.Rva.ToString("X"),
        fileOffset = a.FileOffset >= 0 ? "0x" + a.FileOffset.ToString("X") : null,
        section = a.Section,
        valid = a.Valid,
    };

    // ===================== convert_address =====================

    private static object ConvertAddress(JsonElement args)
    {
        string path = RequirePath(args);
        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new { error = "Not a PE file." };

        var a = TryResolveAddress(args, pe);
        if (a is null)
            return new { error = "Provide one of: address.va, address.rva, address.fileOffset (or inline va/rva/fileOffset)." };

        // Locate the containing section to surface its start/end RVAs and validity bounds.
        string? sectionName = null;
        string? startRva = null, endRva = null;
        bool valid = a.Valid;
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            uint start = (uint)s.VirtualAddress;
            uint end = start + (uint)s.VirtualSize;
            if (a.Rva >= start && a.Rva < end)
            {
                sectionName = s.Name;
                startRva = "0x" + start.ToString("X");
                endRva = "0x" + end.ToString("X");
                break;
            }
        }
        if (sectionName is null && a.Rva != 0) valid = false;

        return new
        {
            path,
            inputNormalized = FormatAddressRef(a),
            va = "0x" + a.Va.ToString("X"),
            rva = "0x" + a.Rva.ToString("X"),
            fileOffset = a.FileOffset >= 0 ? "0x" + a.FileOffset.ToString("X") : null,
            section = sectionName is null ? null : new
            {
                name = sectionName,
                startRva,
                endRva,
                valid = true,
            },
            valid,
        };
    }

    // ===================== resolve_guid =====================

    private static object ResolveGuid(JsonElement args)
    {
        var inputs = new List<string>();
        if (args.TryGetProperty("guid", out var ge) && ge.ValueKind == JsonValueKind.String)
            inputs.Add(ge.GetString() ?? "");
        if (args.TryGetProperty("guids", out var gse) && gse.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in gse.EnumerateArray())
                if (el.ValueKind == JsonValueKind.String) inputs.Add(el.GetString() ?? "");
        }
        inputs = inputs.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();
        if (inputs.Count == 0)
            return new { error = "Missing 'guid' or 'guids' argument." };

        var results = inputs.Select(g =>
        {
            var r = GuidResolver.Resolve(g);
            return new
            {
                guid = r.Guid,
                category = r.Category,
                name = r.Name,
                progID = r.ProgID,
                inprocServer = r.InprocServer,
                localServer = r.LocalServer,
                appID = r.AppId,
                threadingModel = r.ThreadingModel,
                hive = r.Hive,
                registered = r.Category is not null,
            };
        }).ToArray();
        return new { resolved = results };
    }

    // ===================== get_string_at =====================

    private static object GetStringAt(JsonElement args)
    {
        string path = RequirePath(args);
        if (!TryParseNumber(args.GetProperty("offset"), out long offset))
            return new { error = "Couldn't parse 'offset'." };
        string requestedEncoding = args.TryGetProperty("encoding", out var ee) && ee.ValueKind == JsonValueKind.String
            ? ee.GetString() ?? "auto" : "auto";
        int maxLen = args.TryGetProperty("maxLength", out var me) && me.TryGetInt32(out int m)
            ? Math.Clamp(m, 1, 8192) : 1024;

        var bytes = System.IO.File.ReadAllBytes(path);
        if (offset < 0 || offset >= bytes.Length)
            return new { error = $"Offset 0x{offset:X} out of range (file size {bytes.Length})." };

        string encoding = requestedEncoding.ToLowerInvariant();
        if (encoding == "auto")
        {
            // UTF-16LE printable: first char low byte 0x20..0x7E, second byte zero.
            encoding = (offset + 1 < bytes.Length
                        && bytes[offset + 1] == 0
                        && bytes[offset] >= 0x20 && bytes[offset] < 0x7F)
                ? "utf-16le" : "ascii";
        }

        int byteLen;
        string value;
        if (encoding == "utf-16le")
        {
            int end = (int)offset;
            int maxBytes = Math.Min(bytes.Length - (int)offset, maxLen * 2);
            while (end + 1 < (int)offset + maxBytes)
            {
                if (bytes[end] == 0 && bytes[end + 1] == 0) break;
                end += 2;
            }
            byteLen = end - (int)offset;
            value = Encoding.Unicode.GetString(bytes, (int)offset, byteLen);
        }
        else
        {
            int end = (int)offset;
            int maxBytes = Math.Min(bytes.Length - (int)offset, maxLen);
            while (end < (int)offset + maxBytes && bytes[end] != 0) end++;
            byteLen = end - (int)offset;
            value = Encoding.ASCII.GetString(bytes, (int)offset, byteLen);
        }

        return new
        {
            offsetHex = "0x" + offset.ToString("X"),
            encoding,
            byteLength = byteLen,
            charLength = encoding == "utf-16le" ? byteLen / 2 : byteLen,
            value,
        };
    }

    // ===================== find_xrefs =====================

    private static object FindXrefs(JsonElement args)
    {
        string path = RequirePath(args);
        if (!TryParseNumber(args.GetProperty("target"), out long targetLong))
            return new { error = "Couldn't parse 'target'." };
        int hitCap = args.TryGetProperty("max", out var me) && me.TryGetInt32(out int m)
            ? Math.Clamp(m, 1, 10000) : 500;

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new { error = "Not a PE file." };
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "Cross-referencing requires x86/x64." };

        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        ulong imageBase = opt.ImageBase;
        // Allow the user to pass either a VA or a small RVA.
        ulong targetVa = (ulong)targetLong;
        if (targetVa < imageBase) targetVa += imageBase;

        var formatter = new MasmFormatter();
        formatter.Options.DigitSeparator = "";
        var refs = new List<object>();
        long instructionsScanned = 0;

        foreach (var sec in pe.PEHeaders.SectionHeaders)
        {
            if ((sec.SectionCharacteristics & SectionCharacteristics.MemExecute) == 0) continue;
            int off = sec.PointerToRawData;
            int size = sec.SizeOfRawData;
            if (off <= 0 || size <= 0 || off + size > ctx.Bytes.Length) continue;

            var reader = new ByteArrayCodeReader(ctx.Bytes, off, size);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + (ulong)sec.VirtualAddress;
            ulong endIp = decoder.IP + (ulong)size;

            while (decoder.IP < endIp && refs.Count < hitCap)
            {
                ulong instrIp = decoder.IP;
                decoder.Decode(out var instr);
                instructionsScanned++;
                if (instr.IsInvalid) continue;

                bool matched = false;
                string kind = "";

                // Branch / call targets.
                if (instr.IsCallNear || instr.IsJmpNear || instr.IsJmpShort
                    || instr.IsJccNear || instr.IsJccShort)
                {
                    if (instr.NearBranch64 == targetVa) { matched = true; kind = "branch"; }
                }

                // Memory operands and immediates.
                if (!matched)
                {
                    for (int i = 0; i < instr.OpCount; i++)
                    {
                        var kindOp = instr.GetOpKind(i);
                        if (kindOp == OpKind.Memory)
                        {
                            // RIP-relative or absolute memory address.
                            if (instr.IsIPRelativeMemoryOperand)
                            {
                                if (instr.IPRelativeMemoryAddress == targetVa) { matched = true; kind = "mem [rip+disp]"; break; }
                            }
                            else if (instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                            {
                                if ((ulong)instr.MemoryDisplacement64 == targetVa) { matched = true; kind = "mem absolute"; break; }
                            }
                        }
                        else if (kindOp == OpKind.Immediate32 || kindOp == OpKind.Immediate32to64
                              || kindOp == OpKind.Immediate64)
                        {
                            ulong imm = instr.GetImmediate(i);
                            if (imm == targetVa) { matched = true; kind = "immediate"; break; }
                        }
                    }
                }

                if (matched)
                {
                    var output = new StringOutput();
                    formatter.Format(instr, output);
                    refs.Add(new
                    {
                        fromVa = "0x" + instrIp.ToString("X"),
                        fromRva = "0x" + (instrIp - imageBase).ToString("X"),
                        section = sec.Name,
                        kind,
                        text = output.ToString(),
                    });
                }
            }
        }

        return new
        {
            path,
            targetVa = "0x" + targetVa.ToString("X"),
            targetRva = "0x" + (targetVa - imageBase).ToString("X"),
            instructionsScanned,
            referenceCount = refs.Count,
            truncated = refs.Count >= hitCap,
            references = refs,
        };
    }

    // ===================== find_string_refs_ex =====================

    private static object FindStringRefsEx(JsonElement args)
    {
        string path = RequirePath(args);
        string s = args.TryGetProperty("query", out var qe) && qe.ValueKind == JsonValueKind.String
            ? qe.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(s))
        {
            // Back-compat: accept "string" too.
            if (args.TryGetProperty("string", out var se2) && se2.ValueKind == JsonValueKind.String)
                s = se2.GetString() ?? "";
        }
        if (string.IsNullOrEmpty(s)) return new { error = "Missing 'query' argument." };

        string encoding = ArgString(args, "encoding", "auto").ToLowerInvariant();
        bool resolveCodeRefs = !args.TryGetProperty("resolveCodeRefs", out var rce) || rce.ValueKind != JsonValueKind.False;
        int maxHits = args.TryGetProperty("maxHits", out var mhe) && mhe.TryGetInt32(out int mh)
            ? Math.Clamp(mh, 1, 100000) : 1000;
        int maxRefsPerHit = args.TryGetProperty("maxRefsPerHit", out var mre) && mre.TryGetInt32(out int mr)
            ? Math.Clamp(mr, 0, 10000) : 200;

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new { error = "Not a PE file." };
        ulong imageBase = opt.ImageBase;
        bool pe32Plus = opt.Magic == PEMagic.PE32Plus;

        var span = (ReadOnlySpan<byte>)ctx.Bytes;
        var locs = new List<(long FileOffset, string Encoding)>();
        if (encoding == "ascii" || encoding == "auto")
            FindAll(span, Encoding.ASCII.GetBytes(s), "ASCII", locs);
        if (encoding == "utf-16le" || encoding == "auto")
            FindAll(span, Encoding.Unicode.GetBytes(s), "UTF-16LE", locs);

        if (locs.Count > maxHits) locs.RemoveRange(maxHits, locs.Count - maxHits);

        var hits = new List<object>();
        foreach (var (fileOff, enc) in locs)
        {
            long? rva = FileOffsetToRva(pe, (int)fileOff);
            string? section = null;
            string? vaStr = null, rvaStr = null;
            if (rva is not null)
            {
                uint rvaU = (uint)rva.Value;
                vaStr = "0x" + (imageBase + rvaU).ToString("X");
                rvaStr = "0x" + rvaU.ToString("X");
                section = FindSectionForRva(pe, rvaU);
            }

            object[] refs = Array.Empty<object>();
            if (resolveCodeRefs && rva is not null)
            {
                ulong va = imageBase + (ulong)rva.Value;
                var vaBytes = pe32Plus
                    ? BitConverter.GetBytes((ulong)va)
                    : BitConverter.GetBytes((uint)va);
                var sink = new List<object>();
                int from = 0;
                while (sink.Count < maxRefsPerHit && from <= span.Length - vaBytes.Length)
                {
                    int idx = span.Slice(from).IndexOf((ReadOnlySpan<byte>)vaBytes);
                    if (idx < 0) break;
                    int hitOff = from + idx;
                    if (hitOff != (int)fileOff)
                    {
                        long? hitRva = FileOffsetToRva(pe, hitOff);
                        sink.Add(new
                        {
                            refFileOffset = "0x" + hitOff.ToString("X"),
                            refRva = hitRva is long r ? "0x" + r.ToString("X") : null,
                            refVa = hitRva is long r2 ? "0x" + (imageBase + (ulong)r2).ToString("X") : null,
                            section = hitRva is long r3 ? FindSectionForRva(pe, (uint)r3) : null,
                        });
                    }
                    from = hitOff + 1;
                }
                refs = sink.ToArray();
            }

            hits.Add(new
            {
                value = s,
                fileOffset = "0x" + fileOff.ToString("X"),
                va = vaStr,
                rva = rvaStr,
                section,
                encoding = enc,
                refCount = refs.Length,
                refsTruncated = refs.Length >= maxRefsPerHit,
                refs,
            });
        }

        return new
        {
            path,
            query = s,
            hitCount = hits.Count,
            hitsTruncated = hits.Count >= maxHits,
            hits,
        };
    }

    // ===================== disassemble_function / disassemble_nearest_function =====================

    /// <summary>Find the enclosing function for a given RVA using the PeAnalysis index.</summary>
    private static (FunctionInfo? Match, uint NextStart, int Index) FindEnclosingFunction(AnalysisIndex idx, uint rva)
    {
        // Functions are sorted by RVA.
        var fns = idx.Functions;
        int lo = 0, hi = fns.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (fns[mid].Rva <= rva) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (best < 0) return (null, 0, -1);
        uint next = best + 1 < fns.Count ? fns[best + 1].Rva : uint.MaxValue;
        return (fns[best], next, best);
    }

    private static object DisassembleFunction(JsonElement args)
    {
        string path = RequirePath(args);
        bool followTailcalls = args.TryGetProperty("followTailcalls", out var fte) && fte.ValueKind == JsonValueKind.True;
        bool includeImports = !args.TryGetProperty("includeImports", out var iie) || iie.ValueKind != JsonValueKind.False;
        int maxInstr = args.TryGetProperty("maxInstructions", out var mie) && mie.TryGetInt32(out int mv)
            ? Math.Clamp(mv, 1, 200000) : 8000;

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new { error = "Not a PE file." };
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        ulong imageBase = opt.ImageBase;
        bool pe32Plus = bitness == 64;

        var a = TryResolveAddress(args, pe);
        if (a is null || !a.Valid) return new { error = "Provide a valid address (va/rva/fileOffset)." };

        var idx = PeAnalysis.Analyze(ctx);
        if (!idx.Supported) return new { error = "PeAnalysis does not support this binary's architecture." };

        var (match, nextStart, _) = FindEnclosingFunction(idx, a.Rva);
        if (match is null) return new { error = $"No function start at or before RVA 0x{a.Rva:X}." };

        bool exact = match.Rva == a.Rva;
        Confidence conf = exact && match.Confirmed
            ? new Confidence("high", "exact match on confirmed function start (entry/export/TLS)")
            : exact
                ? new Confidence("medium", "exact match on heuristically discovered start")
                : match.Confirmed
                    ? new Confidence("medium", $"snapped backward to nearest confirmed function start (delta {a.Rva - match.Rva} bytes)")
                    : new Confidence("low", $"snapped backward to discovered start (delta {a.Rva - match.Rva} bytes)");

        var iatMap = includeImports ? BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus) : new Dictionary<ulong, string>();
        var (instructions, endRva) = DecodeFunctionBody(
            ctx.Bytes, pe, bitness, imageBase, match.Rva, nextStart, maxInstr, followTailcalls, iatMap);

        return new
        {
            path,
            function = new
            {
                startRva = "0x" + match.Rva.ToString("X"),
                endRva = "0x" + endRva.ToString("X"),
                name = match.Name,
                section = match.Section,
                confidence = new { level = conf.Level, rationale = conf.Rationale },
                reason = exact ? "exact start" : $"snapped to enclosing function (input was 0x{a.Rva:X})",
            },
            instructions,
        };
    }

    private static object DisassembleNearestFunction(JsonElement args)
    {
        string path = RequirePath(args);
        string direction = ArgString(args, "direction", "nearest").ToLowerInvariant();
        int maxDistance = args.TryGetProperty("maxDistanceBytes", out var mde) && mde.TryGetInt32(out int md)
            ? Math.Clamp(md, 0, 1 << 24) : 4096;
        int maxInstr = args.TryGetProperty("maxInstructions", out var mie) && mie.TryGetInt32(out int mv)
            ? Math.Clamp(mv, 1, 200000) : 1024;

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new { error = "Not a PE file." };
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        ulong imageBase = opt.ImageBase;
        bool pe32Plus = bitness == 64;

        var a = TryResolveAddress(args, pe);
        if (a is null) return new { error = "Provide an address (va/rva/fileOffset)." };

        var idx = PeAnalysis.Analyze(ctx);
        if (!idx.Supported) return new { error = "PeAnalysis does not support this binary's architecture." };
        if (idx.Functions.Count == 0) return new { error = "No functions discovered." };

        // Find the nearest function start matching the direction filter.
        FunctionInfo? chosen = null;
        long bestDelta = long.MaxValue;
        foreach (var fn in idx.Functions)
        {
            long delta = (long)fn.Rva - (long)a.Rva;
            switch (direction)
            {
                case "backward": if (delta > 0) continue; break;
                case "forward":  if (delta < 0) continue; break;
                default:         /* nearest */ break;
            }
            long dist = Math.Abs(delta);
            if (dist > maxDistance) continue;
            if (dist < bestDelta) { bestDelta = dist; chosen = fn; }
        }
        if (chosen is null)
            return new { error = $"No function start within {maxDistance} bytes ({direction})." };

        var (_, nextStart, _) = FindEnclosingFunction(idx, chosen.Rva);
        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);
        var (instructions, endRva) = DecodeFunctionBody(
            ctx.Bytes, pe, bitness, imageBase, chosen.Rva, nextStart, maxInstr, followTailcalls: false, iatMap);

        Confidence conf = bestDelta == 0
            ? new Confidence(chosen.Confirmed ? "high" : "medium", chosen.Confirmed ? "exact match" : "exact match on discovered start")
            : new Confidence("medium", $"{direction} snap, distance {bestDelta} bytes");

        return new
        {
            path,
            resolvedFunctionStartRva = "0x" + chosen.Rva.ToString("X"),
            endRva = "0x" + endRva.ToString("X"),
            name = chosen.Name,
            section = chosen.Section,
            distanceBytes = bestDelta,
            confidence = new { level = conf.Level, rationale = conf.Rationale },
            instructions,
        };
    }

    private sealed record Confidence(string Level, string Rationale);

    /// <summary>
    /// Decode a function body from startRva, stopping at the next function start, a ret, or the
    /// next exec-section boundary. Returns the instruction list and computed endRva.
    /// </summary>
    private static (List<object> Instructions, uint EndRva) DecodeFunctionBody(
        byte[] bytes, PEReader pe, int bitness, ulong imageBase,
        uint startRva, uint nextFunctionStart, int maxInstructions, bool followTailcalls,
        Dictionary<ulong, string> iatMap)
    {
        var list = new List<object>(64);
        if (!LanguageInspector.TryRvaToOffset(pe, (int)startRva, out int fileOff))
            return (list, startRva);

        // Stop at the smaller of (next function start) and (end of section's raw data).
        uint sectionEnd = uint.MaxValue;
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            if (startRva >= s.VirtualAddress && startRva < s.VirtualAddress + (uint)s.VirtualSize)
            {
                sectionEnd = (uint)(s.VirtualAddress + s.VirtualSize);
                break;
            }
        }
        uint stopRva = Math.Min(nextFunctionStart, sectionEnd);

        var reader = new ByteArrayCodeReader(bytes, fileOff, bytes.Length - fileOff);
        var decoder = Iced.Intel.Decoder.Create(bitness, reader);
        decoder.IP = imageBase + startRva;
        var formatter = new MasmFormatter();
        formatter.Options.DigitSeparator = "";

        uint endRva = startRva;
        for (int produced = 0; produced < maxInstructions; produced++)
        {
            ulong ip = decoder.IP;
            uint rvaNow = (uint)(ip - imageBase);
            if (rvaNow >= stopRva) break;
            decoder.Decode(out var instr);
            int len = instr.Length;
            if (instr.IsInvalid) break;

            var output = new StringOutput();
            formatter.Format(instr, output);
            var hex = new StringBuilder(len * 3);
            for (int i = 0; i < len; i++)
            {
                hex.Append(bytes[fileOff + (int)(ip - (imageBase + startRva)) + i].ToString("X2"));
                if (i + 1 < len) hex.Append(' ');
            }

            string? annotation = null;
            for (int i = 0; i < instr.OpCount; i++)
            {
                if (instr.GetOpKind(i) != OpKind.Memory) continue;
                ulong memAddr = instr.IsIPRelativeMemoryOperand
                    ? instr.IPRelativeMemoryAddress
                    : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                       ? (ulong)instr.MemoryDisplacement64 : 0UL);
                if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var name)) { annotation = name; break; }
            }

            list.Add(new
            {
                va = "0x" + ip.ToString("X"),
                rva = "0x" + rvaNow.ToString("X"),
                bytes = hex.ToString(),
                text = output.ToString(),
                flowControl = instr.FlowControl.ToString(),
                importTarget = annotation,
            });
            endRva = (uint)(decoder.IP - imageBase);

            if (instr.FlowControl == FlowControl.Return) break;
            // Tailcall = unconditional near jmp to outside this function's range.
            if (!followTailcalls
                && (instr.IsJmpNear || instr.IsJmpShort))
            {
                long tgt = (long)instr.NearBranch64 - (long)imageBase;
                if (tgt < startRva || tgt >= stopRva) break;
            }
        }
        return (list, endRva);
    }

    // ===================== find_xrefs_ex =====================

    private static object FindXrefsEx(JsonElement args)
    {
        string path = RequirePath(args);
        bool resolveThunks = !args.TryGetProperty("resolveThunks", out var rte) || rte.ValueKind != JsonValueKind.False;
        bool includeMem = !args.TryGetProperty("includeIndirectMemoryRefs", out var ime) || ime.ValueKind != JsonValueKind.False;
        bool includeImm = !args.TryGetProperty("includeImmediateRefs", out var iie) || iie.ValueKind != JsonValueKind.False;
        bool includeBranch = !args.TryGetProperty("includeBranchRefs", out var ibe) || ibe.ValueKind != JsonValueKind.False;
        bool groupByFunction = !args.TryGetProperty("groupByFunction", out var gbe) || gbe.ValueKind != JsonValueKind.False;
        int hitCap = args.TryGetProperty("max", out var me) && me.TryGetInt32(out int mc)
            ? Math.Clamp(mc, 1, 100000) : 2000;

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new { error = "Not a PE file." };
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        ulong imageBase = opt.ImageBase;
        bool pe32Plus = bitness == 64;

        var a = TryResolveAddress(args, pe);
        if (a is null) return new { error = "Provide a target (va/rva/fileOffset or top-level 'target')." };
        ulong targetVa = a.Va;

        var idx = PeAnalysis.Analyze(ctx);
        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);

        var formatter = new MasmFormatter();
        formatter.Options.DigitSeparator = "";
        var refs = new List<RefRecord>();
        long instructionsScanned = 0;

        foreach (var sec in pe.PEHeaders.SectionHeaders)
        {
            if ((sec.SectionCharacteristics & SectionCharacteristics.MemExecute) == 0) continue;
            int off = sec.PointerToRawData;
            int size = sec.SizeOfRawData;
            if (off <= 0 || size <= 0 || off + size > ctx.Bytes.Length) continue;

            var reader = new ByteArrayCodeReader(ctx.Bytes, off, size);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + (ulong)sec.VirtualAddress;
            ulong endIp = decoder.IP + (ulong)size;

            while (decoder.IP < endIp && refs.Count < hitCap)
            {
                ulong instrIp = decoder.IP;
                decoder.Decode(out var instr);
                instructionsScanned++;
                if (instr.IsInvalid) continue;

                bool matched = false;
                string kind = "";

                if (includeBranch
                    && (instr.IsCallNear || instr.IsJmpNear || instr.IsJmpShort
                        || instr.IsJccNear || instr.IsJccShort))
                {
                    if (instr.NearBranch64 == targetVa) { matched = true; kind = "branch"; }
                }

                if (!matched)
                {
                    for (int i = 0; i < instr.OpCount; i++)
                    {
                        var k = instr.GetOpKind(i);
                        if (includeMem && k == OpKind.Memory)
                        {
                            if (instr.IsIPRelativeMemoryOperand)
                            {
                                if (instr.IPRelativeMemoryAddress == targetVa) { matched = true; kind = "mem [rip+disp]"; break; }
                            }
                            else if (instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                            {
                                if ((ulong)instr.MemoryDisplacement64 == targetVa) { matched = true; kind = "mem absolute"; break; }
                            }
                        }
                        else if (includeImm && (k == OpKind.Immediate32 || k == OpKind.Immediate32to64 || k == OpKind.Immediate64))
                        {
                            ulong imm = instr.GetImmediate(i);
                            if (imm == targetVa) { matched = true; kind = "immediate"; break; }
                        }
                    }
                }

                if (matched)
                {
                    var output = new StringOutput();
                    formatter.Format(instr, output);
                    refs.Add(new RefRecord
                    {
                        FromVa = instrIp,
                        Section = sec.Name,
                        Kind = kind,
                        Text = output.ToString(),
                    });
                }
            }
        }

        // Annotate enclosing function + thunk-resolve.
        if (idx.Supported)
        {
            foreach (var r in refs)
            {
                uint rrva = (uint)(r.FromVa - imageBase);
                var (fn, _, _) = FindEnclosingFunction(idx, rrva);
                if (fn is not null) r.FromFunctionStartRva = fn.Rva;

                if (resolveThunks)
                {
                    // If the enclosing function is a thunk (first instruction is jmp [iat]),
                    // surface the import it resolves to.
                    if (fn is not null)
                    {
                        var thunk = TryGetThunkTarget(ctx.Bytes, pe, bitness, imageBase, fn.Rva, iatMap);
                        if (thunk is not null) r.ViaThunkTarget = thunk;
                    }
                }
            }
        }

        object[] flatRefs = refs.Select(r => new
        {
            fromVa = "0x" + r.FromVa.ToString("X"),
            fromRva = "0x" + (r.FromVa - imageBase).ToString("X"),
            fromFunctionStartRva = r.FromFunctionStartRva is uint fs ? "0x" + fs.ToString("X") : null,
            section = r.Section,
            kind = r.Kind,
            text = r.Text,
            resolvedFinalTarget = r.ViaThunkTarget,
        }).Cast<object>().ToArray();

        object? groupsOut = null;
        if (groupByFunction)
        {
            groupsOut = refs
                .Where(r => r.FromFunctionStartRva is not null)
                .GroupBy(r => r.FromFunctionStartRva!.Value)
                .OrderByDescending(g => g.Count())
                .Select(g => new
                {
                    functionStartRva = "0x" + g.Key.ToString("X"),
                    count = g.Count(),
                    firstSites = g.Take(5).Select(r => "0x" + (r.FromVa - imageBase).ToString("X")).ToArray(),
                })
                .Cast<object>()
                .ToArray();
        }

        return new
        {
            path,
            targetNormalized = new
            {
                va = "0x" + targetVa.ToString("X"),
                rva = "0x" + (targetVa - imageBase).ToString("X"),
            },
            instructionsScanned,
            referenceCount = refs.Count,
            truncated = refs.Count >= hitCap,
            references = flatRefs,
            groups = groupsOut,
        };
    }

    private sealed class RefRecord
    {
        public ulong FromVa { get; set; }
        public string Section { get; set; } = "";
        public string Kind { get; set; } = "";
        public string Text { get; set; } = "";
        public uint? FromFunctionStartRva { get; set; }
        public string? ViaThunkTarget { get; set; }
    }

    /// <summary>
    /// If the function at functionRva is a thunk (its first instruction is jmp [iat_slot]),
    /// return the "dll!function" name. Otherwise null.
    /// </summary>
    private static string? TryGetThunkTarget(
        byte[] bytes, PEReader pe, int bitness, ulong imageBase,
        uint functionRva, Dictionary<ulong, string> iatMap)
    {
        if (!LanguageInspector.TryRvaToOffset(pe, (int)functionRva, out int fileOff)) return null;
        var reader = new ByteArrayCodeReader(bytes, fileOff, Math.Min(16, bytes.Length - fileOff));
        var decoder = Iced.Intel.Decoder.Create(bitness, reader);
        decoder.IP = imageBase + functionRva;
        decoder.Decode(out var instr);
        if (instr.IsInvalid) return null;
        if (!(instr.IsJmpNearIndirect || instr.IsJmpFarIndirect || instr.IsJmpNear || instr.IsJmpShort))
            return null;
        for (int i = 0; i < instr.OpCount; i++)
        {
            if (instr.GetOpKind(i) != OpKind.Memory) continue;
            ulong memAddr = instr.IsIPRelativeMemoryOperand
                ? instr.IPRelativeMemoryAddress
                : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                   ? (ulong)instr.MemoryDisplacement64 : 0UL);
            if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var name)) return name;
        }
        return null;
    }

    // ===================== get_pe_map =====================

    private static object GetPeMap(JsonElement args)
    {
        string path = RequirePath(args);
        string format = ArgString(args, "format", "mermaid");

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var sections = pe.PEHeaders.SectionHeaders;
        var dlls = PeImports.Read(pe, out _);
        var resources = PeResources.Walk(ctx.Bytes);
        var resourceTypes = resources
            .GroupBy(r => r.TypeDisplay)
            .Select(g => new { type = g.Key, count = g.Count(), totalBytes = g.Sum(r => (long)r.Size) })
            .OrderByDescending(g => g.totalBytes)
            .ToList();

        if (format == "json")
        {
            return new
            {
                path = ctx.Path,
                sections = sections.Select(s => new
                {
                    name = s.Name,
                    fileOffset = "0x" + s.PointerToRawData.ToString("X"),
                    rawSize = s.SizeOfRawData,
                    characteristics = s.SectionCharacteristics.ToString(),
                }).ToArray(),
                imports = dlls.Select(d => new { dll = d.Dll, functionCount = d.Functions.Count }).ToArray(),
                resources = resourceTypes,
            };
        }

        var sb = new StringBuilder();
        sb.AppendLine("flowchart LR");
        sb.AppendLine($"  PE([\"{System.IO.Path.GetFileName(path)}\"])");
        sb.AppendLine("  subgraph SECTIONS [\"Sections\"]");
        int i = 0;
        foreach (var s in sections)
            sb.AppendLine($"    S{i++}[\"{Escape(s.Name)}\\n{FormatBytes(s.SizeOfRawData)}\"]");
        sb.AppendLine("  end");
        sb.AppendLine("  subgraph IMPORTS [\"Imports\"]");
        i = 0;
        foreach (var d in dlls)
            sb.AppendLine($"    I{i++}[\"{Escape(d.Dll)}\\n{d.Functions.Count} fn(s)\"]");
        sb.AppendLine("  end");
        if (resourceTypes.Count > 0)
        {
            sb.AppendLine("  subgraph RESOURCES [\"Resources\"]");
            i = 0;
            foreach (var r in resourceTypes)
                sb.AppendLine($"    R{i++}[\"{Escape(r.type)}\\n{r.count} entr(ies), {FormatBytes(r.totalBytes)}\"]");
            sb.AppendLine("  end");
        }
        sb.AppendLine("  PE --> SECTIONS");
        sb.AppendLine("  PE --> IMPORTS");
        if (resourceTypes.Count > 0) sb.AppendLine("  PE --> RESOURCES");
        return new { path, format = "mermaid", mermaid = sb.ToString() };
    }

    // ===================== get_call_graph =====================

    private sealed record CallEdge(uint From, string ToId, string ToLabel, bool IsImport);

    private static object GetCallGraph(JsonElement args)
    {
        string path = RequirePath(args);
        int depth = args.TryGetProperty("depth", out var de) && de.TryGetInt32(out int d)
            ? Math.Clamp(d, 1, 5) : 2;
        string format = ArgString(args, "format", "mermaid");

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader ?? throw new InvalidOperationException("Not a PE file.");
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "Call graph is x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        bool pe32Plus = bitness == 64;
        ulong imageBase = opt.ImageBase;

        uint startRva;
        if (args.TryGetProperty("rva", out var re) && TryParseNumber(re, out long rl))
            startRva = (uint)rl;
        else
            startRva = (uint)opt.AddressOfEntryPoint;
        if (startRva == 0) return new { error = "No starting RVA and binary has no entry point." };

        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);
        var fnNames = new Dictionary<uint, string>();
        foreach (var ex in InterfacesInspector.ReadExports(ctx.Bytes, pe)) fnNames[ex.Rva] = ex.Name;

        var nodes = new Dictionary<uint, string>();
        var edges = new List<CallEdge>();
        var visited = new HashSet<uint>();
        var queue = new Queue<(uint Rva, int D)>();
        queue.Enqueue((startRva, 0));

        while (queue.Count > 0)
        {
            var (rva, currentDepth) = queue.Dequeue();
            if (!visited.Add(rva)) continue;
            string label = fnNames.TryGetValue(rva, out var n) ? n : $"sub_{rva:X}";
            nodes[rva] = label;
            if (currentDepth >= depth) continue;

            if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int fileOff)) continue;
            var reader = new ByteArrayCodeReader(ctx.Bytes, fileOff, ctx.Bytes.Length - fileOff);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + rva;
            for (int j = 0; j < 5000; j++)
            {
                decoder.Decode(out var instr);
                if (instr.IsInvalid) break;
                if (instr.IsCallNear)
                {
                    long targetRva = (long)instr.NearBranch64 - (long)imageBase;
                    if (targetRva > 0 && targetRva < uint.MaxValue)
                    {
                        uint tRva = (uint)targetRva;
                        string toLabel = fnNames.TryGetValue(tRva, out var nm) ? nm : $"sub_{tRva:X}";
                        edges.Add(new CallEdge(rva, $"N_{tRva:X}", toLabel, false));
                        queue.Enqueue((tRva, currentDepth + 1));
                    }
                }
                else if (instr.IsCallNearIndirect)
                {
                    for (int op = 0; op < instr.OpCount; op++)
                    {
                        if (instr.GetOpKind(op) != OpKind.Memory) continue;
                        ulong memAddr = instr.IsIPRelativeMemoryOperand
                            ? instr.IPRelativeMemoryAddress
                            : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                               ? (ulong)instr.MemoryDisplacement64 : 0UL);
                        if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var importName))
                        {
                            string impId = "IMP_" + SanitizeId(importName);
                            edges.Add(new CallEdge(rva, impId, importName, true));
                            break;
                        }
                    }
                }
                if (instr.FlowControl == FlowControl.Return) break;
            }
        }

        if (format == "json")
        {
            return new
            {
                path,
                start = "0x" + startRva.ToString("X"),
                nodeCount = nodes.Count,
                edgeCount = edges.Count,
                nodes = nodes.Select(kv => new { id = "N_" + kv.Key.ToString("X"), rva = "0x" + kv.Key.ToString("X"), label = kv.Value }).ToArray(),
                edges = edges.Select(e => new { from = "N_" + e.From.ToString("X"), to = e.ToId, target = e.ToLabel, isImport = e.IsImport }).ToArray(),
            };
        }

        var sb = new StringBuilder();
        sb.AppendLine("flowchart TD");
        foreach (var kv in nodes)
            sb.AppendLine($"  N_{kv.Key:X}[\"{Escape(kv.Value)}\"]");
        var seenImpIds = new HashSet<string>();
        foreach (var e in edges.Where(x => x.IsImport))
        {
            if (seenImpIds.Add(e.ToId))
                sb.AppendLine($"  {e.ToId}([\"{Escape(e.ToLabel)}\"])");
        }
        foreach (var e in edges)
            sb.AppendLine($"  N_{e.From:X} --> {e.ToId}");
        return new { path, format = "mermaid", start = "0x" + startRva.ToString("X"), mermaid = sb.ToString() };
    }

    // ===================== summarize_import_usage =====================

    private sealed record ImportUsageEntry(
        string Dll,
        string Function,
        ulong IatSlotVa,
        List<(ulong FromVa, string Section)> Callsites)
    {
        public bool Truncated { get; set; }
    }

    private static object SummarizeImportUsage(JsonElement args)
    {
        string path = RequirePath(args);
        bool resolveThunks = !args.TryGetProperty("resolveThunks", out var rte) || rte.ValueKind != JsonValueKind.False;
        int maxCallsites = args.TryGetProperty("maxCallsitesPerImport", out var mce) && mce.TryGetInt32(out int mc)
            ? Math.Clamp(mc, 1, 100000) : 200;
        var dllFilter = ParseStringSet(args, "includeDllFilter");
        var fnFilter  = ParseStringSet(args, "includeFunctionFilter");

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new { error = "Not a PE file." };
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        bool pe32Plus = bitness == 64;
        ulong imageBase = opt.ImageBase;

        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);
        if (iatMap.Count == 0)
            return new { path, importCount = 0, instructionsScanned = 0, imports = Array.Empty<object>() };

        var idx = PeAnalysis.Analyze(ctx);

        // thunk function RVA -> resolved import "dll!fn"
        var thunkRvaToImport = new Dictionary<uint, string>();
        if (resolveThunks && idx.Supported)
        {
            foreach (var fn in idx.Functions)
            {
                var t = TryGetThunkTarget(ctx.Bytes, pe, bitness, imageBase, fn.Rva, iatMap);
                if (t is not null) thunkRvaToImport[fn.Rva] = t;
            }
        }

        bool PassesFilter(string fullName)
        {
            if (dllFilter is null && fnFilter is null) return true;
            int bang = fullName.IndexOf('!');
            string dll = bang > 0 ? fullName[..bang] : "";
            string fn = bang > 0 ? fullName[(bang + 1)..] : fullName;
            if (dllFilter is not null && !dllFilter.Contains(dll)) return false;
            if (fnFilter is not null && !fnFilter.Contains(fn)) return false;
            return true;
        }

        // Build entries (one per IAT slot that passes the filter).
        var entries = new Dictionary<string, ImportUsageEntry>(StringComparer.Ordinal);
        foreach (var kv in iatMap)
        {
            if (!PassesFilter(kv.Value)) continue;
            int bang = kv.Value.IndexOf('!');
            string dll = bang > 0 ? kv.Value[..bang] : "";
            string fn = bang > 0 ? kv.Value[(bang + 1)..] : kv.Value;
            entries[kv.Value] = new ImportUsageEntry(dll, fn, kv.Key, new List<(ulong, string)>());
        }

        void AddCallsite(string name, ulong fromVa, string section)
        {
            if (!entries.TryGetValue(name, out var e)) return;
            if (e.Callsites.Count < maxCallsites) e.Callsites.Add((fromVa, section));
            else e.Truncated = true;
        }

        long instructionsScanned = 0;
        foreach (var sec in pe.PEHeaders.SectionHeaders)
        {
            if ((sec.SectionCharacteristics & SectionCharacteristics.MemExecute) == 0) continue;
            int off = sec.PointerToRawData;
            int size = sec.SizeOfRawData;
            if (off <= 0 || size <= 0 || off + size > ctx.Bytes.Length) continue;

            var reader = new ByteArrayCodeReader(ctx.Bytes, off, size);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + (ulong)sec.VirtualAddress;
            ulong endIp = decoder.IP + (ulong)size;

            while (decoder.IP < endIp)
            {
                ulong instrIp = decoder.IP;
                decoder.Decode(out var instr);
                instructionsScanned++;
                if (instr.IsInvalid) continue;

                // Direct call/jmp landing on a thunk wrapping an import.
                if (resolveThunks && (instr.IsCallNear || instr.IsJmpNear || instr.IsJmpShort))
                {
                    long tgt = (long)instr.NearBranch64 - (long)imageBase;
                    if (tgt > 0 && tgt < uint.MaxValue
                        && thunkRvaToImport.TryGetValue((uint)tgt, out var thunkImport)
                        && entries.ContainsKey(thunkImport))
                    {
                        AddCallsite(thunkImport, instrIp, sec.Name);
                        continue;
                    }
                }

                // Indirect through IAT slot.
                if (instr.IsCallNearIndirect || instr.IsJmpNearIndirect)
                {
                    for (int op = 0; op < instr.OpCount; op++)
                    {
                        if (instr.GetOpKind(op) != OpKind.Memory) continue;
                        ulong memAddr = instr.IsIPRelativeMemoryOperand
                            ? instr.IPRelativeMemoryAddress
                            : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                               ? (ulong)instr.MemoryDisplacement64 : 0UL);
                        if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var importName) && entries.ContainsKey(importName))
                        {
                            // Avoid double-counting: if this instruction IS the thunk's own jmp [iat],
                            // skip — direct callers of the thunk are already counted above.
                            if (resolveThunks && idx.Supported)
                            {
                                uint instrRva = (uint)(instrIp - imageBase);
                                if (thunkRvaToImport.TryGetValue(instrRva, out var thunkImp)
                                    && string.Equals(thunkImp, importName, StringComparison.Ordinal))
                                {
                                    break;
                                }
                            }
                            AddCallsite(importName, instrIp, sec.Name);
                            break;
                        }
                    }
                }
            }
        }

        // Build output: order by total callsites desc.
        var ordered = entries.Values.OrderByDescending(e => e.Callsites.Count).ToList();
        var importsOut = new List<object>(ordered.Count);
        foreach (var e in ordered)
        {
            var uniqueCallers = new HashSet<uint>();
            var callsiteObjs = new List<object>(e.Callsites.Count);
            foreach (var c in e.Callsites)
            {
                uint? fnRva = null;
                string? fnName = null;
                if (idx.Supported)
                {
                    var (f, _, _) = FindEnclosingFunction(idx, (uint)(c.FromVa - imageBase));
                    if (f is not null) { fnRva = f.Rva; fnName = f.Name; uniqueCallers.Add(f.Rva); }
                }
                callsiteObjs.Add(new
                {
                    fromVa = "0x" + c.FromVa.ToString("X"),
                    fromRva = "0x" + (c.FromVa - imageBase).ToString("X"),
                    fromFunctionStartRva = fnRva is uint r ? "0x" + r.ToString("X") : null,
                    fromFunctionName = fnName,
                    section = c.Section,
                });
            }
            importsOut.Add(new
            {
                dll = e.Dll,
                function = e.Function,
                iatSlotVa = "0x" + e.IatSlotVa.ToString("X"),
                iatSlotRva = "0x" + (e.IatSlotVa - imageBase).ToString("X"),
                totalCallsites = e.Callsites.Count,
                uniqueCallerFunctions = uniqueCallers.Count,
                callsitesTruncated = e.Truncated,
                callsites = callsiteObjs,
            });
        }

        return new
        {
            path,
            instructionsScanned,
            importCount = importsOut.Count,
            imports = importsOut,
        };
    }

    private static HashSet<string>? ParseStringSet(JsonElement args, string name)
    {
        if (!args.TryGetProperty(name, out var e) || e.ValueKind != JsonValueKind.Array) return null;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var el in e.EnumerateArray())
            if (el.ValueKind == JsonValueKind.String) set.Add(el.GetString() ?? "");
        return set.Count == 0 ? null : set;
    }

    // ===================== architecture_evidence_pack (v0) =====================

    private static async Task<object> ArchitectureEvidencePack(JsonElement args)
    {
        string path = RequirePath(args);

        var scope = args.TryGetProperty("scope", out var se) && se.ValueKind == JsonValueKind.Object ? se : default;
        var opts  = args.TryGetProperty("options", out var oe) && oe.ValueKind == JsonValueKind.Object ? oe : default;

        int maxFunctions = ScopeInt(scope, "maxFunctions", 2000);
        int maxEdges     = ScopeInt(scope, "maxEdges", 10000);
        bool includeStrings  = ScopeBool(scope, "includeStrings", true);
        bool includeImports  = ScopeBool(scope, "includeImports", true);
        bool includeSections = ScopeBool(scope, "includeSections", true);

        bool resolveThunks   = ScopeBool(opts, "resolveThunks", true);
        bool includeFindings = ScopeBool(opts, "includeInspectorFindings", true);
        bool inferTeardown   = ScopeBool(opts, "inferInitTeardownCandidates", true);
        bool includePerFn    = ScopeBool(opts, "includePerFunctionFeatures", true);

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt2 = pe.PEHeaders.PEHeader;
        if (opt2 is null) return new { error = "Not a PE file." };
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "Evidence pack requires x86/x64." };
        int bitness = opt2.Magic == PEMagic.PE32Plus ? 64 : 32;
        bool pe32Plus = bitness == 64;
        ulong imageBase = opt2.ImageBase;
        uint entryRva = (uint)opt2.AddressOfEntryPoint;
        if (scope.ValueKind == JsonValueKind.Object
            && scope.TryGetProperty("entryRva", out var ere)
            && TryParseNumber(ere, out long erl))
        {
            entryRva = (uint)erl;
        }

        string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ctx.Bytes)).ToLowerInvariant();

        // ===== binary.sections =====
        object[] sectionsOut = includeSections
            ? pe.PEHeaders.SectionHeaders.Select(sec => (object)new
            {
                name = sec.Name,
                startRva = "0x" + sec.VirtualAddress.ToString("X"),
                endRva = "0x" + (sec.VirtualAddress + sec.VirtualSize).ToString("X"),
                characteristics = SectionCharFlags(sec.SectionCharacteristics).ToArray(),
            }).ToArray()
            : Array.Empty<object>();

        // ===== imports =====
        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);
        object[] dllsOut = Array.Empty<object>();
        object[] functionsOut = Array.Empty<object>();
        object[] usageOut = Array.Empty<object>();
        if (includeImports)
        {
            var dlls = PeImports.Read(pe, out _);
            dllsOut = dlls.Select(d => (object)new { name = d.Dll, functionCount = d.Functions.Count }).ToArray();
            var fnReverse = new Dictionary<string, ulong>(StringComparer.Ordinal);
            foreach (var kv in iatMap) fnReverse.TryAdd(kv.Value, kv.Key);
            var fnList = new List<object>();
            foreach (var d in dlls)
            {
                string norm = d.Dll;
                foreach (var ext in new[] { ".dll", ".DLL" })
                    if (norm.EndsWith(ext)) { norm = norm[..^ext.Length]; break; }
                foreach (var fn in d.Functions)
                {
                    string full = $"{norm}!{fn}";
                    fnReverse.TryGetValue(full, out var slotVa);
                    fnList.Add(new
                    {
                        dll = d.Dll,
                        name = fn,
                        iatRva = slotVa == 0 ? null : "0x" + (slotVa - imageBase).ToString("X"),
                    });
                }
            }
            functionsOut = fnList.ToArray();

            // Reuse SummarizeImportUsage by re-serialize/parse — keeps a single source of truth.
            using var usageArgs = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                path,
                resolveThunks,
                maxCallsitesPerImport = 200,
            }));
            var usagePayload = SummarizeImportUsage(usageArgs.RootElement);
            using var usageDoc = JsonDocument.Parse(JsonSerializer.Serialize(usagePayload));
            if (usageDoc.RootElement.TryGetProperty("imports", out var importsEl))
            {
                string ruleId = resolveThunks ? "import-usage-group-v1+thunk-collapse-v1" : "import-usage-group-v1";
                usageOut = importsEl.EnumerateArray().Select(im =>
                {
                    var callsites = im.GetProperty("callsites").EnumerateArray().Select(c => new
                    {
                        fromRva = c.GetProperty("fromRva").GetString(),
                        fromFunctionRva = c.TryGetProperty("fromFunctionStartRva", out var ffsr)
                            && ffsr.ValueKind == JsonValueKind.String ? ffsr.GetString() : null,
                        section = c.GetProperty("section").GetString(),
                    }).ToArray();
                    var callerFns = callsites
                        .Where(c => c.fromFunctionRva is not null)
                        .Select(c => c.fromFunctionRva!)
                        .Distinct()
                        .ToArray();
                    return (object)new
                    {
                        dll = im.GetProperty("dll").GetString(),
                        function = im.GetProperty("function").GetString(),
                        callsiteCount = im.GetProperty("totalCallsites").GetInt32(),
                        callerFunctions = callerFns,
                        callsites,
                        provenance = new
                        {
                            sourceTools = new[] { "summarize_import_usage", "find_function_starts" },
                            ruleId,
                        },
                    };
                }).ToArray();
            }
        }

        // ===== controlFlow =====
        var idx = PeAnalysis.Analyze(ctx);
        object[] functionStartsOut = Array.Empty<object>();
        object callGraphSummary = new { nodeCount = 0, edgeCount = 0, importEdgeCount = 0, internalEdgeCount = 0 };
        object[] entryReachableOut = Array.Empty<object>();
        var entryReachableSet = new HashSet<uint>();
        bool ctrlFlowTruncated = false;
        if (idx.Supported)
        {
            ctrlFlowTruncated = idx.Functions.Count > maxFunctions;
            functionStartsOut = idx.Functions
                .Take(maxFunctions)
                .Select(f => (object)new
                {
                    rva = "0x" + f.Rva.ToString("X"),
                    name = f.Name,
                    confirmed = f.Confirmed,
                    section = f.Section,
                }).ToArray();

            if (entryRva != 0)
            {
                var summary = ComputeEntryReachable(ctx.Bytes, pe, bitness, imageBase, entryRva, iatMap, maxFunctions, maxEdges);
                entryReachableOut = summary.Reachable;
                entryReachableSet = summary.ReachableSet;
                callGraphSummary = new
                {
                    nodeCount = summary.NodeCount,
                    edgeCount = summary.EdgeCount,
                    importEdgeCount = summary.ImportEdgeCount,
                    internalEdgeCount = summary.EdgeCount - summary.ImportEdgeCount,
                };
                if (summary.Truncated) ctrlFlowTruncated = true;
            }
        }

        // ===== features + teardown candidates (v1 / v2) =====
        object[] teardownOut = Array.Empty<object>();
        object[] perFunctionOut = Array.Empty<object>();
        if (idx.Supported && (inferTeardown || includePerFn))
        {
            // thunk function RVA -> resolved import.
            var thunkMap = new Dictionary<uint, string>();
            foreach (var fn in idx.Functions)
            {
                var t = TryGetThunkTarget(ctx.Bytes, pe, bitness, imageBase, fn.Rva, iatMap);
                if (t is not null) thunkMap[fn.Rva] = t;
            }
            var stringVaSet  = BuildStringVaSet(ctx.Bytes, pe, imageBase);
            var unwindBegins = BuildUnwindBeginSet(pe, ctx.Bytes);

            var (perFn, teardown) = await Task.Run(() => ComputeFunctionFeatures(
                ctx.Bytes, pe, bitness, imageBase, idx, iatMap, thunkMap,
                stringVaSet, unwindBegins, entryReachableSet, maxFunctions,
                wantPerFunction: includePerFn, wantTeardown: inferTeardown)).ConfigureAwait(false);
            perFunctionOut = perFn;
            teardownOut = teardown;
        }

        // ===== strings =====
        object stringsOut = new { total = 0, hits = Array.Empty<object>(), refs = Array.Empty<object>() };
        if (includeStrings)
        {
            var stringsInspector = new StringsInspector();
            var stringsResult = await stringsInspector.InspectAsync(ctx).ConfigureAwait(false);
            const int stringsCap = 1000;
            var hits = stringsResult.Findings.Take(stringsCap).Select((f, i) => (object)new
            {
                id = "str_" + i,
                value = f.Value ?? f.Title,
                encoding = (string?)null,
                fileOffset = (string?)null,
                rva = (string?)null,
                section = (string?)null,
            }).ToArray();
            stringsOut = new
            {
                total = stringsResult.Findings.Count,
                truncated = stringsResult.Findings.Count > stringsCap,
                hits,
                refs = Array.Empty<object>(),
            };
        }

        // ===== inspectorFindings =====
        object inspectorFindingsOut = new { findings = Array.Empty<object>(), normalized = Array.Empty<object>() };
        if (includeFindings)
        {
            var inspectors = BinaryLoader.DefaultInspectors;
            var tasks = inspectors.Select(i => i.InspectAsync(ctx)).ToArray();
            var results = await Task.WhenAll(tasks).ConfigureAwait(false);
            var findings = new List<object>();
            var normalized = new List<object>();
            foreach (var r in results)
            {
                for (int i = 0; i < r.Findings.Count; i++)
                {
                    var f = r.Findings[i];
                    findings.Add(new
                    {
                        inspector = r.InspectorName,
                        title = f.Title,
                        value = f.Value,
                        details = f.Details,
                        severity = f.Severity.ToString(),
                    });
                    normalized.Add(new
                    {
                        findingId = $"{r.InspectorName}#{i}",
                        inspector = r.InspectorName,
                        key = f.Title,
                        value = f.Value ?? "",
                        severity = f.Severity.ToString(),
                        rawIndex = i,
                    });
                }
            }
            inspectorFindingsOut = new
            {
                findings = findings.ToArray(),
                normalized = normalized.ToArray(),
            };
        }

        // ===== meta + provenance =====
        var meta = new
        {
            schemaVersion = "0.1.0",
            generatedAtUtc = DateTime.UtcNow.ToString("o"),
            binaryHashSha256 = sha256,
            truncated = ctrlFlowTruncated,
            limitsApplied = new { maxFunctions, maxEdges },
        };

        var provenance = new
        {
            tools = new[]
            {
                "list_imports", "find_function_starts", "summarize_import_usage",
                "find_xrefs_ex", "inspect",
            },
            derivationRules = new object[]
            {
                new { ruleId = "sections-pe-header-v1", description = "PE section table read directly from the optional header.", deterministic = true, version = "0.1.0" },
                new { ruleId = "function-starts-pe-analysis-v1", description = "Function discovery: entry/exports/TLS confirmed; call-target heuristic for discovered.", deterministic = true, version = "0.1.0" },
                new { ruleId = "import-usage-group-v1", description = "Indirect call/jmp instructions whose memory operand resolves to an IAT slot, grouped by destination slot and source function.", deterministic = true, version = "0.1.0" },
                new { ruleId = "thunk-collapse-v1", description = "Functions whose first instruction is jmp [iat_slot] are treated as thunks; direct callers are attributed to the wrapped import.", deterministic = true, version = "0.1.0" },
                new { ruleId = "entry-reachable-bfs-v1", description = "BFS from the entry RVA following direct near-call targets, depth-bounded.", deterministic = true, version = "0.1.0" },
                new { ruleId = "inspector-normalize-v1", description = "Inspector findings normalized to (inspector, key, value, severity, rawIndex) tuples.", deterministic = true, version = "0.1.0" },
                new { ruleId = "teardown-candidate-apis-v1", description = "A function is scored by the count of distinct imports it calls whose name starts with a teardown-flavored prefix (Delete/Destroy/Free/Unregister/Unload/Close/Disconnect/Cleanup/Uninitialize/...). No init/unload phase is claimed.", deterministic = true, version = "0.1.0" },
                new { ruleId = "per-function-feature-pack-v1", description = "Per-function counters from one linear decode between adjacent discovered function starts: instruction/call/branch/import counts, unique imports, string-VA references, outgoing call targets, incoming xrefs (PeAnalysis), x64 .pdata unwind presence.", deterministic = true, version = "0.1.0" },
            },
            fieldSources = new object[]
            {
                new { field = "binary.sections", ruleId = "sections-pe-header-v1" },
                new { field = "imports.functions", ruleId = "sections-pe-header-v1" },
                new { field = "imports.usage", ruleId = "import-usage-group-v1" },
                new { field = "controlFlow.functionStarts", ruleId = "function-starts-pe-analysis-v1" },
                new { field = "controlFlow.entryReachable", ruleId = "entry-reachable-bfs-v1" },
                new { field = "controlFlow.teardownCandidates", ruleId = "teardown-candidate-apis-v1" },
                new { field = "features.perFunction", ruleId = "per-function-feature-pack-v1" },
                new { field = "inspectorFindings.normalized", ruleId = "inspector-normalize-v1" },
            },
        };

        return new
        {
            meta,
            binary = new
            {
                path,
                imageBase = "0x" + imageBase.ToString("X"),
                entryRva = "0x" + entryRva.ToString("X"),
                bitness,
                sections = sectionsOut,
            },
            imports = new
            {
                dlls = dllsOut,
                functions = functionsOut,
                usage = usageOut,
            },
            strings = stringsOut,
            controlFlow = new
            {
                functionStarts = functionStartsOut,
                callGraphSummary,
                entryReachable = entryReachableOut,
                teardownCandidates = teardownOut,
            },
            features = new
            {
                perFunction = perFunctionOut,
                global = ComputeGlobalFeatures(perFunctionOut, idx, iatMap),
            },
            inspectorFindings = inspectorFindingsOut,
            provenance,
        };
    }

    private static int ScopeInt(JsonElement el, string name, int fallback)
    {
        if (el.ValueKind != JsonValueKind.Object) return fallback;
        if (!el.TryGetProperty(name, out var v)) return fallback;
        return v.TryGetInt32(out int i) ? i : fallback;
    }

    private static bool ScopeBool(JsonElement el, string name, bool fallback)
    {
        if (el.ValueKind != JsonValueKind.Object) return fallback;
        if (!el.TryGetProperty(name, out var v)) return fallback;
        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => fallback,
        };
    }

    private static IEnumerable<string> SectionCharFlags(SectionCharacteristics c)
    {
        if ((c & SectionCharacteristics.MemExecute) != 0) yield return "EXECUTE";
        if ((c & SectionCharacteristics.MemRead) != 0) yield return "READ";
        if ((c & SectionCharacteristics.MemWrite) != 0) yield return "WRITE";
        if ((c & SectionCharacteristics.ContainsCode) != 0) yield return "CODE";
        if ((c & SectionCharacteristics.ContainsInitializedData) != 0) yield return "INITIALIZED_DATA";
        if ((c & SectionCharacteristics.ContainsUninitializedData) != 0) yield return "UNINITIALIZED_DATA";
        if ((c & SectionCharacteristics.MemDiscardable) != 0) yield return "DISCARDABLE";
        if ((c & SectionCharacteristics.MemShared) != 0) yield return "SHARED";
    }

    private sealed record EntryReachableSummary(
        object[] Reachable,
        HashSet<uint> ReachableSet,
        int NodeCount,
        int EdgeCount,
        int ImportEdgeCount,
        bool Truncated);

    private static EntryReachableSummary ComputeEntryReachable(
        byte[] bytes, PEReader pe, int bitness, ulong imageBase,
        uint startRva, Dictionary<ulong, string> iatMap, int maxNodes, int maxEdges)
    {
        var visited = new Dictionary<uint, int>();
        var q = new Queue<(uint Rva, int D)>();
        q.Enqueue((startRva, 0));
        int edgeCount = 0;
        int importEdgeCount = 0;
        bool truncated = false;

        while (q.Count > 0)
        {
            if (visited.Count >= maxNodes || edgeCount >= maxEdges) { truncated = true; break; }
            var (rva, d) = q.Dequeue();
            if (visited.ContainsKey(rva)) continue;
            visited[rva] = d;
            if (d >= 8) continue;
            if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int fileOff)) continue;
            var reader = new ByteArrayCodeReader(bytes, fileOff, bytes.Length - fileOff);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + rva;
            for (int j = 0; j < 5000; j++)
            {
                decoder.Decode(out var instr);
                if (instr.IsInvalid) break;
                if (instr.IsCallNear)
                {
                    long t = (long)instr.NearBranch64 - (long)imageBase;
                    if (t > 0 && t < uint.MaxValue) { q.Enqueue(((uint)t, d + 1)); edgeCount++; }
                }
                else if (instr.IsCallNearIndirect)
                {
                    for (int op = 0; op < instr.OpCount; op++)
                    {
                        if (instr.GetOpKind(op) != OpKind.Memory) continue;
                        ulong memAddr = instr.IsIPRelativeMemoryOperand
                            ? instr.IPRelativeMemoryAddress
                            : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                               ? (ulong)instr.MemoryDisplacement64 : 0UL);
                        if (memAddr != 0 && iatMap.ContainsKey(memAddr)) { edgeCount++; importEdgeCount++; break; }
                    }
                }
                if (instr.FlowControl == FlowControl.Return) break;
            }
        }

        var reachable = visited
            .OrderBy(kv => kv.Value).ThenBy(kv => kv.Key)
            .Select(kv => (object)new
            {
                functionRva = "0x" + kv.Key.ToString("X"),
                depth = kv.Value,
                via = kv.Key == startRva ? "entry" : "call",
            }).ToArray();

        return new EntryReachableSummary(reachable, new HashSet<uint>(visited.Keys),
            visited.Count, edgeCount, importEdgeCount, truncated);
    }

    // ===================== evidence-pack feature helpers (v1 / v2) =====================

    private static readonly string[] TeardownApiPrefixes =
    {
        "Delete", "Destroy", "Free", "Unregister", "UnRegister", "Deregister", "DeRegister",
        "Unload", "Unmap", "UnMap", "Disconnect", "Cleanup", "Uninitialize", "Unadvise",
        "Unhook", "Revoke", "Terminate", "Shutdown", "Close", "Release",
    };

    private static bool IsTeardownApi(string importFullName, out string apiName)
    {
        int bang = importFullName.IndexOf('!');
        apiName = bang >= 0 ? importFullName[(bang + 1)..] : importFullName;
        foreach (var p in TeardownApiPrefixes)
            if (apiName.StartsWith(p, StringComparison.Ordinal)) return true;
        return false;
    }

    private static string? ResolveMemImport(in Iced.Intel.Instruction instr, Dictionary<ulong, string> iatMap)
    {
        for (int op = 0; op < instr.OpCount; op++)
        {
            if (instr.GetOpKind(op) != OpKind.Memory) continue;
            ulong memAddr = instr.IsIPRelativeMemoryOperand
                ? instr.IPRelativeMemoryAddress
                : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                   ? (ulong)instr.MemoryDisplacement64 : 0UL);
            if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var name)) return name;
        }
        return null;
    }

    /// <summary>Record the start VA of every null-terminated ASCII / UTF-16LE string in data sections.</summary>
    private static HashSet<ulong> BuildStringVaSet(byte[] bytes, PEReader pe, ulong imageBase)
    {
        var set = new HashSet<ulong>();
        foreach (var sec in pe.PEHeaders.SectionHeaders)
        {
            if ((sec.SectionCharacteristics & SectionCharacteristics.MemExecute) != 0) continue;
            if ((sec.SectionCharacteristics & SectionCharacteristics.ContainsInitializedData) == 0) continue;
            int off = sec.PointerToRawData;
            int size = sec.SizeOfRawData;
            if (off <= 0 || size <= 0 || off + size > bytes.Length) continue;
            int end = off + size;

            int i = off;
            while (i < end)
            {
                int runStart = i, len = 0;
                while (i < end && bytes[i] >= 0x20 && bytes[i] < 0x7F) { i++; len++; }
                if (len >= 5 && i < end && bytes[i] == 0)
                    set.Add(imageBase + (ulong)(sec.VirtualAddress + (runStart - off)));
                i++;
            }
            i = off;
            while (i + 1 < end)
            {
                int runStart = i, len = 0;
                while (i + 1 < end && bytes[i] >= 0x20 && bytes[i] < 0x7F && bytes[i + 1] == 0) { i += 2; len++; }
                if (len >= 5)
                    set.Add(imageBase + (ulong)(sec.VirtualAddress + (runStart - off)));
                i += 2;
            }
            if (set.Count > 300000) break;
        }
        return set;
    }

    /// <summary>x64 only: BeginAddress of every RUNTIME_FUNCTION in the exception directory.</summary>
    private static HashSet<uint> BuildUnwindBeginSet(PEReader pe, byte[] bytes)
    {
        var set = new HashSet<uint>();
        var dir = pe.PEHeaders.PEHeader?.ExceptionTableDirectory;
        if (dir is null || dir.Value.Size == 0) return set;
        if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int off)) return set;
        int count = dir.Value.Size / 12;
        for (int i = 0; i < count; i++)
        {
            int p = off + i * 12;
            if (p + 12 > bytes.Length) break;
            set.Add(BitConverter.ToUInt32(bytes, p));
        }
        return set;
    }

    private static (object[] PerFunction, object[] Teardown) ComputeFunctionFeatures(
        byte[] bytes, PEReader pe, int bitness, ulong imageBase,
        AnalysisIndex idx, Dictionary<ulong, string> iatMap, Dictionary<uint, string> thunkMap,
        HashSet<ulong> stringVaSet, HashSet<uint> unwindBeginSet, HashSet<uint> entryReachableSet,
        int maxFunctions, bool wantPerFunction, bool wantTeardown)
    {
        var perFunction = new List<object>();
        var teardown = new List<object>();
        var formatter = new MasmFormatter();
        formatter.Options.DigitSeparator = "";
        var fns = idx.Functions;
        int limit = Math.Min(fns.Count, maxFunctions);

        for (int fi = 0; fi < limit; fi++)
        {
            var fn = fns[fi];
            uint startRva = fn.Rva;
            uint stopRva = fi + 1 < fns.Count ? fns[fi + 1].Rva : uint.MaxValue;
            if (!LanguageInspector.TryRvaToOffset(pe, (int)startRva, out int fileOff)) continue;

            var reader = new ByteArrayCodeReader(bytes, fileOff, bytes.Length - fileOff);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + startRva;

            int instrCount = 0, callCount = 0, branchCount = 0, importCalls = 0, stringRefs = 0;
            var uniqueImports = new HashSet<string>(StringComparer.Ordinal);
            var outgoing = new HashSet<uint>();
            var teardownApis = new HashSet<string>(StringComparer.Ordinal);
            var teardownEvidence = new List<object>();
            bool isThunk = thunkMap.ContainsKey(startRva);

            for (int j = 0; j < 30000; j++)
            {
                ulong ip = decoder.IP;
                if ((uint)(ip - imageBase) >= stopRva) break;
                decoder.Decode(out var instr);
                if (instr.IsInvalid) break;
                instrCount++;
                uint instrRva = (uint)(ip - imageBase);

                if (instr.IsCallNear || instr.IsCallNearIndirect) callCount++;
                if (instr.IsJmpNear || instr.IsJmpShort || instr.IsJccNear || instr.IsJccShort) branchCount++;

                string? resolvedImport = null;
                if (instr.IsCallNear)
                {
                    long t = (long)instr.NearBranch64 - (long)imageBase;
                    if (t > 0 && t < uint.MaxValue)
                    {
                        uint tr = (uint)t;
                        if (thunkMap.TryGetValue(tr, out var thunkImp)) resolvedImport = thunkImp;
                        else outgoing.Add(tr);
                    }
                }
                else if (instr.IsCallNearIndirect)
                {
                    resolvedImport = ResolveMemImport(instr, iatMap);
                }

                if (resolvedImport is not null)
                {
                    importCalls++;
                    uniqueImports.Add(resolvedImport);
                    if (wantTeardown && IsTeardownApi(resolvedImport, out var apiName))
                    {
                        teardownApis.Add(apiName);
                        if (teardownEvidence.Count < 16)
                        {
                            var output = new StringOutput();
                            formatter.Format(instr, output);
                            teardownEvidence.Add(new
                            {
                                rva = "0x" + instrRva.ToString("X"),
                                text = output.ToString(),
                                ruleId = "teardown-candidate-apis-v1",
                            });
                        }
                    }
                }

                for (int op = 0; op < instr.OpCount; op++)
                {
                    var k = instr.GetOpKind(op);
                    ulong addr = 0;
                    if (k == OpKind.Memory)
                    {
                        addr = instr.IsIPRelativeMemoryOperand
                            ? instr.IPRelativeMemoryAddress
                            : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                               ? (ulong)instr.MemoryDisplacement64 : 0UL);
                    }
                    else if (k is OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64)
                    {
                        addr = instr.GetImmediate(op);
                    }
                    if (addr != 0 && stringVaSet.Contains(addr)) { stringRefs++; break; }
                }

                // For the final function (no next start) stop at a ret followed by int3 padding.
                if (instr.FlowControl == FlowControl.Return && stopRva == uint.MaxValue)
                {
                    int nextOff = fileOff + (int)(decoder.IP - (imageBase + startRva));
                    if (nextOff >= bytes.Length || bytes[nextOff] == 0xCC) break;
                }
            }

            int incomingRefs = idx.Xrefs.TryGetValue(imageBase + startRva, out var xl) ? xl.Count : 0;
            bool hasSeh = unwindBeginSet.Contains(startRva);

            if (wantTeardown && teardownApis.Count > 0)
            {
                teardown.Add(new
                {
                    functionRva = "0x" + startRva.ToString("X"),
                    score = teardownApis.Count,
                    triggers = teardownApis.OrderBy(s => s).ToArray(),
                    evidence = teardownEvidence.ToArray(),
                });
            }

            if (wantPerFunction)
            {
                var tags = new List<string>();
                if (isThunk) tags.Add("thunk");
                if (callCount == 0) tags.Add("leaf");
                if (importCalls >= 8) tags.Add("imports-heavy");
                if (incomingRefs == 0) tags.Add("no-incoming-refs");
                if (entryReachableSet.Contains(startRva)) tags.Add("entry-reachable");
                if (hasSeh) tags.Add("has-seh");
                if (teardownApis.Count > 0) tags.Add("teardown-candidate");
                if (fn.Confirmed) tags.Add("confirmed-start");

                perFunction.Add(new
                {
                    functionRva = "0x" + startRva.ToString("X"),
                    section = fn.Section,
                    instructionCount = instrCount,
                    callCount,
                    branchCount,
                    importCalls,
                    uniqueImports = uniqueImports.OrderBy(s => s).ToArray(),
                    stringRefCount = stringRefs,
                    outgoingCalls = outgoing.Count,
                    incomingRefs,
                    hasSehUnwind = hasSeh,
                    tags = tags.ToArray(),
                    provenance = new
                    {
                        ruleId = "per-function-feature-pack-v1",
                        sourceTools = new[] { "find_function_starts", "disassemble_function" },
                    },
                });
            }
        }

        return (perFunction.ToArray(),
                teardown.OrderByDescending(t => (int)t.GetType().GetProperty("score")!.GetValue(t)!).ToArray());
    }

    private static object ComputeGlobalFeatures(object[] perFunction, AnalysisIndex idx, Dictionary<ulong, string> iatMap)
    {
        long totalImportCalls = 0;
        long totalStringRefs = 0;
        long totalInstr = 0;
        var sectionHistogram = new Dictionary<string, int>();
        var importFamilyHistogram = new Dictionary<string, int>();

        foreach (var pf in perFunction)
        {
            var t = pf.GetType();
            totalImportCalls += Convert.ToInt32(t.GetProperty("importCalls")!.GetValue(pf));
            totalStringRefs  += Convert.ToInt32(t.GetProperty("stringRefCount")!.GetValue(pf));
            totalInstr       += Convert.ToInt32(t.GetProperty("instructionCount")!.GetValue(pf));
            string sec = t.GetProperty("section")!.GetValue(pf) as string ?? "(none)";
            sectionHistogram[sec] = sectionHistogram.GetValueOrDefault(sec) + 1;
        }
        foreach (var name in iatMap.Values)
        {
            int bang = name.IndexOf('!');
            string dll = bang > 0 ? name[..bang] : "(unknown)";
            importFamilyHistogram[dll] = importFamilyHistogram.GetValueOrDefault(dll) + 1;
        }

        return new
        {
            totalFunctions = idx.Supported ? idx.Functions.Count : 0,
            totalImportSlots = iatMap.Count,
            totalImportCalls,
            totalInstructions = totalInstr,
            importFamilyHistogram,
            sectionFunctionHistogram = sectionHistogram,
            stringRefDensity = totalInstr > 0 ? Math.Round((double)totalStringRefs / totalInstr, 6) : 0.0,
        };
    }

    // ===================== get_call_graph_ex =====================

    private sealed record CallGraphNode(uint Rva, string Label, bool IsImport);

    private static object GetCallGraphEx(JsonElement args)
    {
        string path = RequirePath(args);
        int depth = args.TryGetProperty("depth", out var de) && de.TryGetInt32(out int d)
            ? Math.Clamp(d, 1, 8) : 2;
        bool followCond = args.TryGetProperty("followConditionalBranches", out var fce) && fce.ValueKind == JsonValueKind.True;
        bool includeTailCalls = !args.TryGetProperty("includeTailCalls", out var ite) || ite.ValueKind != JsonValueKind.False;
        bool resolveThunks = !args.TryGetProperty("resolveThunks", out var rte) || rte.ValueKind != JsonValueKind.False;
        bool includeImports = !args.TryGetProperty("includeImports", out var iie) || iie.ValueKind != JsonValueKind.False;
        bool pruneImports = args.TryGetProperty("pruneImports", out var pie) && pie.ValueKind == JsonValueKind.True;
        int maxNodes = args.TryGetProperty("maxNodes", out var mne) && mne.TryGetInt32(out int mn)
            ? Math.Clamp(mn, 1, 50000) : 2000;
        int maxEdges = args.TryGetProperty("maxEdges", out var mee) && mee.TryGetInt32(out int me)
            ? Math.Clamp(me, 1, 200000) : 10000;
        string format = ArgString(args, "format", "json").ToLowerInvariant();

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader ?? throw new InvalidOperationException("Not a PE file.");
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "Call graph is x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        bool pe32Plus = bitness == 64;
        ulong imageBase = opt.ImageBase;

        var startA = TryResolveAddress(args, pe);
        uint startRva = startA?.Rva ?? (uint)opt.AddressOfEntryPoint;
        if (startRva == 0) return new { error = "No starting address and binary has no entry point." };

        var idx = PeAnalysis.Analyze(ctx);
        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);
        var fnNames = new Dictionary<uint, string>();
        foreach (var ex in InterfacesInspector.ReadExports(ctx.Bytes, pe)) fnNames[ex.Rva] = ex.Name;
        foreach (var fn in idx.Functions) if (!fnNames.ContainsKey(fn.Rva)) fnNames[fn.Rva] = fn.Name;

        var nodes = new Dictionary<uint, string>();      // rva -> label  (internal functions)
        var importNodes = new Dictionary<string, string>(); // import id -> label
        var edges = new List<(uint From, string ToId, string ToLabel, bool IsImport, string Kind)>();
        var visited = new HashSet<uint>();
        var queue = new Queue<(uint Rva, int D)>();
        queue.Enqueue((startRva, 0));

        bool truncated = false;
        while (queue.Count > 0)
        {
            if (nodes.Count >= maxNodes || edges.Count >= maxEdges) { truncated = true; break; }
            var (rva, currentDepth) = queue.Dequeue();
            if (!visited.Add(rva)) continue;
            string label = fnNames.TryGetValue(rva, out var n) ? n : $"sub_{rva:X}";
            nodes[rva] = label;
            if (currentDepth >= depth) continue;

            if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int fileOff)) continue;

            // Determine the enclosing function's stopRva so tail-call detection works.
            uint stopRva = uint.MaxValue;
            if (idx.Supported)
            {
                var (match, nextStart, _) = FindEnclosingFunction(idx, rva);
                if (match is not null && match.Rva == rva) stopRva = nextStart;
            }

            var reader = new ByteArrayCodeReader(ctx.Bytes, fileOff, ctx.Bytes.Length - fileOff);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + rva;
            for (int j = 0; j < 8000; j++)
            {
                decoder.Decode(out var instr);
                if (instr.IsInvalid) break;
                uint instrRva = (uint)(instr.IP - imageBase);
                if (instrRva >= stopRva) break;

                void AddInternalEdge(uint tRva, string kind)
                {
                    string toLabel = fnNames.TryGetValue(tRva, out var nm) ? nm : $"sub_{tRva:X}";

                    if (resolveThunks)
                    {
                        var thunkTarget = TryGetThunkTarget(ctx.Bytes, pe, bitness, imageBase, tRva, iatMap);
                        if (thunkTarget is not null && includeImports)
                        {
                            string impId = "IMP_" + SanitizeId(thunkTarget);
                            importNodes[impId] = thunkTarget;
                            edges.Add((rva, impId, thunkTarget, true, kind + "→thunk"));
                            return;
                        }
                    }

                    edges.Add((rva, "N_" + tRva.ToString("X"), toLabel, false, kind));
                    queue.Enqueue((tRva, currentDepth + 1));
                }

                if (instr.IsCallNear)
                {
                    long t = (long)instr.NearBranch64 - (long)imageBase;
                    if (t > 0 && t < uint.MaxValue) AddInternalEdge((uint)t, "call");
                }
                else if (instr.IsCallNearIndirect)
                {
                    if (!includeImports) continue;
                    for (int op = 0; op < instr.OpCount; op++)
                    {
                        if (instr.GetOpKind(op) != OpKind.Memory) continue;
                        ulong memAddr = instr.IsIPRelativeMemoryOperand
                            ? instr.IPRelativeMemoryAddress
                            : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                               ? (ulong)instr.MemoryDisplacement64 : 0UL);
                        if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var importName))
                        {
                            string impId = "IMP_" + SanitizeId(importName);
                            importNodes[impId] = importName;
                            edges.Add((rva, impId, importName, true, "indirect"));
                            break;
                        }
                    }
                }
                else if (includeTailCalls && (instr.IsJmpNear || instr.IsJmpShort))
                {
                    long t = (long)instr.NearBranch64 - (long)imageBase;
                    // Only count as tail call when leaving the enclosing function.
                    if (t > 0 && t < uint.MaxValue && ((uint)t < rva || (uint)t >= stopRva))
                        AddInternalEdge((uint)t, "tailcall");
                }
                else if (followCond && (instr.IsJccNear || instr.IsJccShort))
                {
                    long t = (long)instr.NearBranch64 - (long)imageBase;
                    if (t > 0 && t < uint.MaxValue && ((uint)t < rva || (uint)t >= stopRva))
                        AddInternalEdge((uint)t, "cond-branch");
                }

                if (instr.FlowControl == FlowControl.Return) break;
            }
        }

        if (pruneImports)
        {
            importNodes.Clear();
            edges.RemoveAll(e => e.IsImport);
        }

        if (format == "mermaid")
        {
            var sb = new StringBuilder();
            sb.AppendLine("flowchart TD");
            foreach (var kv in nodes)
                sb.AppendLine($"  N_{kv.Key:X}[\"{Escape(kv.Value)}\"]");
            foreach (var kv in importNodes)
                sb.AppendLine($"  {kv.Key}([\"{Escape(kv.Value)}\"])");
            foreach (var e in edges)
                sb.AppendLine($"  N_{e.From:X} -- {e.Kind} --> {e.ToId}");
            return new
            {
                path,
                start = "0x" + startRva.ToString("X"),
                format = "mermaid",
                mermaid = sb.ToString(),
                stats = new { nodesVisited = nodes.Count + importNodes.Count, edgesVisited = edges.Count, truncated },
            };
        }

        return new
        {
            path,
            start = "0x" + startRva.ToString("X"),
            nodes = nodes
                .Select(kv => new { id = "N_" + kv.Key.ToString("X"), rva = "0x" + kv.Key.ToString("X"), label = kv.Value, isImport = false })
                .Concat(importNodes.Select(kv => new { id = kv.Key, rva = "0x0", label = kv.Value, isImport = true }))
                .ToArray(),
            edges = edges.Select(e => new
            {
                from = "N_" + e.From.ToString("X"),
                to = e.ToId,
                target = e.ToLabel,
                isImport = e.IsImport,
                kind = e.Kind,
            }).ToArray(),
            stats = new { nodesVisited = nodes.Count + importNodes.Count, edgesVisited = edges.Count, truncated },
        };
    }

    // ===================== get_init_sequence =====================

    private static object GetInitSequence(JsonElement args)
    {
        string path = RequirePath(args);
        int depth = args.TryGetProperty("depth", out var de) && de.TryGetInt32(out int d)
            ? Math.Clamp(d, 1, 32) : 8;
        string format = ArgString(args, "format", "mermaid");

        var ctx = new BinaryContext(path);
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader ?? throw new InvalidOperationException("Not a PE file.");
        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new { error = "x86/x64 only." };
        int bitness = opt.Magic == PEMagic.PE32Plus ? 64 : 32;
        bool pe32Plus = bitness == 64;
        ulong imageBase = opt.ImageBase;

        uint startRva;
        if (args.TryGetProperty("rva", out var re) && TryParseNumber(re, out long rl))
            startRva = (uint)rl;
        else
            startRva = (uint)opt.AddressOfEntryPoint;
        if (startRva == 0) return new { error = "No starting RVA and binary has no entry point." };

        var iatMap = BuildIatMap(pe, ctx.Bytes, imageBase, pe32Plus);
        var fnNames = new Dictionary<uint, string>();
        foreach (var ex in InterfacesInspector.ReadExports(ctx.Bytes, pe)) fnNames[ex.Rva] = ex.Name;

        // Linearly walk the first-call chain: at each function, dive into the first non-import
        // call. Stop on import, ret, or depth limit. Records every call seen at each level.
        var steps = new List<(string From, string To, bool IsImport)>();
        var visited = new HashSet<uint>();
        uint current = startRva;
        for (int lvl = 0; lvl < depth; lvl++)
        {
            if (!visited.Add(current)) break;
            string fromLabel = fnNames.TryGetValue(current, out var fn) ? fn : $"sub_{current:X}";
            if (!LanguageInspector.TryRvaToOffset(pe, (int)current, out int fileOff)) break;

            var reader = new ByteArrayCodeReader(ctx.Bytes, fileOff, ctx.Bytes.Length - fileOff);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            decoder.IP = imageBase + current;
            uint? nextDirect = null;
            for (int j = 0; j < 5000; j++)
            {
                decoder.Decode(out var instr);
                if (instr.IsInvalid) break;
                if (instr.IsCallNear)
                {
                    long tRva = (long)instr.NearBranch64 - (long)imageBase;
                    if (tRva > 0 && tRva < uint.MaxValue)
                    {
                        string toLabel = fnNames.TryGetValue((uint)tRva, out var tn) ? tn : $"sub_{tRva:X}";
                        steps.Add((fromLabel, toLabel, false));
                        if (nextDirect is null) nextDirect = (uint)tRva;
                    }
                }
                else if (instr.IsCallNearIndirect)
                {
                    for (int op = 0; op < instr.OpCount; op++)
                    {
                        if (instr.GetOpKind(op) != OpKind.Memory) continue;
                        ulong memAddr = instr.IsIPRelativeMemoryOperand
                            ? instr.IPRelativeMemoryAddress
                            : ((instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                               ? (ulong)instr.MemoryDisplacement64 : 0UL);
                        if (memAddr != 0 && iatMap.TryGetValue(memAddr, out var importName))
                            steps.Add((fromLabel, importName, true));
                    }
                }
                if (instr.FlowControl == FlowControl.Return) break;
            }
            if (nextDirect is null) break;
            current = nextDirect.Value;
        }

        if (format == "json")
        {
            return new
            {
                path,
                start = "0x" + startRva.ToString("X"),
                stepCount = steps.Count,
                steps = steps.Select(s => new { from = s.From, to = s.To, isImport = s.IsImport }).ToArray(),
            };
        }

        var sb = new StringBuilder();
        sb.AppendLine("sequenceDiagram");
        var participants = new HashSet<string>();
        foreach (var s in steps)
        {
            if (participants.Add(s.From))
                sb.AppendLine($"  participant {SanitizeId(s.From)} as {s.From}");
            if (participants.Add(s.To))
                sb.AppendLine($"  participant {SanitizeId(s.To)} as {s.To}");
        }
        foreach (var s in steps)
        {
            string arrow = s.IsImport ? "->>" : "->>+";
            sb.AppendLine($"  {SanitizeId(s.From)} {arrow} {SanitizeId(s.To)}: call");
        }
        return new { path, format = "mermaid", start = "0x" + startRva.ToString("X"), mermaid = sb.ToString() };
    }

    private static string SanitizeId(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(char.IsLetterOrDigit(c) || c == '_' ? c : '_');
        if (sb.Length == 0 || char.IsDigit(sb[0])) sb.Insert(0, '_');
        return sb.ToString();
    }

    private static string Escape(string s)
        => s.Replace("\"", "&quot;").Replace("\n", "\\n");

    private static string FormatBytes(long n)
    {
        if (n < 1024) return $"{n} B";
        if (n < 1024 * 1024) return $"{n / 1024.0:F1} KB";
        return $"{n / (1024.0 * 1024):F1} MB";
    }

    private static string ArgString(JsonElement args, string name, string fallback)
        => args.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? fallback : fallback;

    // ===================== IAT map helper =====================

    /// <summary>Build a map from IAT slot VA -&gt; "dll!function" name. Used by disassemble to annotate `call qword ptr [iat_slot]`.</summary>
    internal static Dictionary<ulong, string> BuildIatMap(PEReader pe, byte[] bytes, ulong imageBase, bool pe32Plus)
    {
        var map = new Dictionary<ulong, string>();
        var dir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return map;
        if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int offset)) return map;

        int thunkSize = pe32Plus ? 8 : 4;
        ulong ordinalFlag = pe32Plus ? 0x8000000000000000UL : 0x80000000UL;

        while (offset + 20 <= bytes.Length)
        {
            uint originalFirstThunk = BitConverter.ToUInt32(bytes, offset);
            uint nameRva = BitConverter.ToUInt32(bytes, offset + 12);
            uint firstThunk = BitConverter.ToUInt32(bytes, offset + 16);
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            string dllName = "?";
            if (nameRva != 0 && LanguageInspector.TryRvaToOffset(pe, (int)nameRva, out int nameOff))
            {
                int end = nameOff;
                while (end < bytes.Length && bytes[end] != 0) end++;
                dllName = Encoding.ASCII.GetString(bytes, nameOff, end - nameOff);
            }

            // Walk the ILT (OriginalFirstThunk) to get names; the IAT (FirstThunk) gives us slot RVAs.
            uint nameTableRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (nameTableRva != 0 && firstThunk != 0
                && LanguageInspector.TryRvaToOffset(pe, (int)nameTableRva, out int iltOff))
            {
                int i = 0;
                while (iltOff + thunkSize <= bytes.Length)
                {
                    ulong thunk = pe32Plus
                        ? BitConverter.ToUInt64(bytes, iltOff)
                        : BitConverter.ToUInt32(bytes, iltOff);
                    if (thunk == 0) break;

                    string funcName;
                    if ((thunk & ordinalFlag) != 0)
                    {
                        ushort ord = (ushort)(thunk & 0xFFFF);
                        funcName = $"#{ord}";
                    }
                    else
                    {
                        int hintNameRva = (int)(thunk & 0x7FFFFFFF);
                        if (LanguageInspector.TryRvaToOffset(pe, hintNameRva, out int hnOff) && hnOff + 2 < bytes.Length)
                        {
                            int nameEnd = hnOff + 2;
                            while (nameEnd < bytes.Length && bytes[nameEnd] != 0) nameEnd++;
                            funcName = Encoding.ASCII.GetString(bytes, hnOff + 2, nameEnd - (hnOff + 2));
                        }
                        else funcName = "(unnamed)";
                    }

                    ulong slotVa = imageBase + (ulong)firstThunk + (ulong)(i * thunkSize);
                    string norm = dllName;
                    foreach (var ext in new[] { ".dll", ".DLL" })
                        if (norm.EndsWith(ext)) { norm = norm[..^ext.Length]; break; }
                    map[slotVa] = $"{norm}!{funcName}";

                    iltOff += thunkSize;
                    i++;
                }
            }
            offset += 20;
        }
        return map;
    }

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

    /// <summary>
    /// Resolve the binary path for a tool call. Resolution order:
    ///   explicit 'path' argument  ->  MCP session target  ->  file open in the UI.
    /// </summary>
    private static string RequirePath(JsonElement args)
    {
        string? path = null;
        if (args.ValueKind == JsonValueKind.Object
            && args.TryGetProperty("path", out var p)
            && p.ValueKind == JsonValueKind.String)
        {
            string s = p.GetString() ?? "";
            if (!string.IsNullOrWhiteSpace(s)) path = s;
        }
        path ??= McpSession.CurrentTargetPath;
        path ??= AppState.Instance.Binary?.Path;
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException(
                "No 'path' given and no current target. Pass 'path', call set_current_target, "
                + "or open a file in BinaryExplorer.");
        if (!System.IO.File.Exists(path))
            throw new FileNotFoundException($"File not found: {path}");
        return path;
    }

    // ===================== current target (session state) =====================

    private static object SetCurrentTarget(JsonElement args)
    {
        if (!args.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String)
            return new { error = "Missing 'path' argument." };
        string path = p.GetString() ?? "";
        if (string.IsNullOrWhiteSpace(path))
            return new { error = "'path' is empty." };
        if (!System.IO.File.Exists(path))
            return new { error = $"File not found: {path}" };
        McpSession.CurrentTargetPath = path;
        return new { ok = true, currentTarget = path };
    }

    private static object GetCurrentTarget(JsonElement args)
    {
        string? session = McpSession.CurrentTargetPath;
        string? ui = AppState.Instance.Binary?.Path;
        string? effective = session ?? ui;
        return new
        {
            sessionTarget = session,
            appUiTarget = ui,
            effectiveTarget = effective,
            source = session is not null ? "session" : ui is not null ? "app-ui" : "none",
        };
    }

    private static object ClearCurrentTarget(JsonElement args)
    {
        string? prev = McpSession.CurrentTargetPath;
        McpSession.CurrentTargetPath = null;
        return new { ok = true, cleared = prev };
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
