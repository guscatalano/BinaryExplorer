using System.Reflection.PortableExecutable;
using System.Text;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class InterfacesInspector : IBinaryInspector
{
    public string Name => "Interfaces";

    private static readonly HashSet<string> ComServerExports = new(StringComparer.Ordinal)
    {
        "DllRegisterServer",
        "DllUnregisterServer",
        "DllGetClassObject",
        "DllCanUnloadNow",
        "DllInstall",
        "DllGetActivationFactory",
    };

    private static readonly Dictionary<string, string> ComApis = new(StringComparer.Ordinal)
    {
        ["CoCreateInstance"]        = "create a COM object by CLSID",
        ["CoCreateInstanceEx"]      = "create a COM object on a remote machine",
        ["CoCreateInstanceFromApp"] = "create a COM object (AppContainer)",
        ["CoGetClassObject"]        = "get a COM class factory",
        ["CoGetObject"]             = "bind to a moniker",
        ["CoRegisterClassObject"]   = "register a COM class factory (server)",
        ["CoRevokeClassObject"]     = "unregister a COM class factory",
        ["CoInitialize"]            = "init COM (STA)",
        ["CoInitializeEx"]          = "init COM with threading model",
        ["CoMarshalInterface"]      = "marshal an interface pointer",
        ["CoUnmarshalInterface"]    = "unmarshal an interface pointer",
        ["CoImpersonateClient"]     = "impersonate COM client",
        ["DllGetClassObject"]       = "in-process server class factory",
        ["DllRegisterServer"]       = "self-registration entry point",
        ["RoActivateInstance"]      = "WinRT activation",
        ["RoGetActivationFactory"]  = "WinRT activation factory",
    };

    private static readonly Dictionary<string, string> RpcApis = new(StringComparer.Ordinal)
    {
        // ----- server-side -----
        ["RpcServerRegisterIf"]       = "register RPC interface",
        ["RpcServerRegisterIf2"]      = "register RPC interface (v2)",
        ["RpcServerRegisterIfEx"]     = "register RPC interface (Ex)",
        ["RpcServerListen"]           = "start listening for RPC calls",
        ["RpcServerUseProtseq"]       = "use a protocol sequence",
        ["RpcServerUseProtseqEp"]     = "use a protocol sequence + endpoint",
        ["RpcServerUseProtseqEpA"]    = "use a protocol sequence + endpoint (A)",
        ["RpcServerUseProtseqEpW"]    = "use a protocol sequence + endpoint (W)",
        ["RpcServerUseProtseqIf"]     = "use a protocol sequence for interface",
        ["NdrServerInitializeNew"]    = "MIDL-generated server stub init",
        ["NdrServerCall2"]            = "MIDL-generated server stub call dispatch",
        ["NdrServerCallAll"]          = "MIDL-generated server stub (full)",
        ["RpcEpRegister"]             = "register endpoint with mapper",
        ["RpcEpUnregister"]           = "unregister endpoint",
        // ----- client-side -----
        ["RpcBindingFromStringBinding"]  = "create client binding from string",
        ["RpcBindingFromStringBindingA"] = "create client binding from string (A)",
        ["RpcBindingFromStringBindingW"] = "create client binding from string (W)",
        ["RpcStringBindingCompose"]      = "compose a binding string",
        ["RpcStringBindingComposeA"]     = "compose a binding string (A)",
        ["RpcStringBindingComposeW"]     = "compose a binding string (W)",
        ["RpcBindingSetAuthInfo"]        = "set auth info on binding",
        ["RpcBindingSetAuthInfoEx"]      = "set auth info on binding (Ex)",
        ["NdrClientCall"]                = "MIDL-generated client stub (v1)",
        ["NdrClientCall2"]               = "MIDL-generated client stub (v2)",
        ["NdrClientCall3"]               = "MIDL-generated client stub (v3)",
        ["NdrClientCall4"]               = "MIDL-generated client stub (v4)",
        ["NdrAsyncClientCall"]           = "MIDL-generated async client stub",
    };

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var ms = new MemoryStream(context.Bytes, writable: false);
                using var pe = new PEReader(ms);

                // --- 1. COM-server exports ---
                var exports = ReadExports(context.Bytes, pe);
                var comExportsHit = exports
                    .Where(e => ComServerExports.Contains(e.Name))
                    .ToList();
                bool isComServer = comExportsHit.Count > 0;

                if (isComServer)
                {
                    findings.Add(new Finding(
                        "COM in-process server",
                        $"{comExportsHit.Count} signature export(s)",
                        string.Join("\n", comExportsHit.Select(e => $"  {e.Name}  (RVA 0x{e.Rva:X})")),
                        Severity.Info));
                }

                // --- 2. COM and RPC API imports ---
                var imports = PeImports.Read(pe, out _);
                var allFns = imports
                    .SelectMany(d => d.Functions.Select(f => (Dll: d.Dll, Fn: f)))
                    .ToList();

                var comCalls = allFns.Where(p => ComApis.ContainsKey(p.Fn)).ToList();
                if (comCalls.Count > 0)
                {
                    findings.Add(new Finding(
                        "COM / WinRT client APIs",
                        $"{comCalls.Count} API(s)",
                        string.Join("\n", comCalls
                            .OrderBy(p => p.Fn, StringComparer.Ordinal)
                            .Select(p => $"  {p.Fn}  ({p.Dll}) — {ComApis[p.Fn]}")),
                        Severity.Info));
                }

                var rpcCalls = allFns.Where(p => RpcApis.ContainsKey(p.Fn)).ToList();
                bool rpcServer = rpcCalls.Any(p => p.Fn.StartsWith("RpcServer", StringComparison.Ordinal)
                                             || p.Fn == "NdrServerInitializeNew"
                                             || p.Fn == "NdrServerCall2"
                                             || p.Fn == "NdrServerCallAll"
                                             || p.Fn == "RpcEpRegister");
                bool rpcClient = rpcCalls.Any(p => p.Fn.StartsWith("RpcBinding", StringComparison.Ordinal)
                                             || p.Fn.StartsWith("NdrClientCall", StringComparison.Ordinal)
                                             || p.Fn.StartsWith("RpcStringBinding", StringComparison.Ordinal)
                                             || p.Fn == "NdrAsyncClientCall");
                if (rpcCalls.Count > 0)
                {
                    string role = (rpcServer, rpcClient) switch
                    {
                        (true,  true)  => "RPC server + client APIs",
                        (true,  false) => "RPC server APIs",
                        (false, true)  => "RPC client APIs",
                        _              => "RPC APIs (role unclear)",
                    };
                    findings.Add(new Finding(
                        role,
                        $"{rpcCalls.Count} API(s)",
                        string.Join("\n", rpcCalls
                            .OrderBy(p => p.Fn, StringComparer.Ordinal)
                            .Select(p => $"  {p.Fn}  ({p.Dll}) — {RpcApis[p.Fn]}")),
                        rpcServer ? Severity.Warning : Severity.Info));
                }

                // --- 2a. RPC server interfaces (parse RPC_SERVER_INTERFACE structs) ---
                bool pe32Plus = pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus;
                ulong imageBase = pe.PEHeaders.PEHeader?.ImageBase ?? 0;
                var exportRvaToName = exports.ToDictionary(e => e.Rva, e => e.Name);
                var rpcInterfaces = FindRpcServerInterfaces(context.Bytes, pe, imageBase, pe32Plus);
                if (rpcInterfaces.Count > 0)
                {
                    int totalMethods = rpcInterfaces.Sum(i => i.MethodCount);
                    findings.Add(new Finding(
                        "RPC server interfaces exposed",
                        $"{rpcInterfaces.Count} interface(s), {totalMethods} method(s)",
                        "Parsed from RPC_SERVER_INTERFACE structures (anchored via NDR20/NDR64 transfer-syntax UUID).",
                        Severity.Warning));
                    foreach (var iface in rpcInterfaces)
                    {
                        findings.Add(new Finding(
                            $"RPC interface v{iface.MajorVersion}.{iface.MinorVersion}",
                            iface.Uuid,
                            $"File offset: 0x{iface.FileOffset:X8}    Transfer syntax: {iface.TransferSyntax}    Methods: {iface.MethodCount}    Struct length: {iface.StructLength} bytes",
                            Severity.Warning));
                        if (iface.MethodRvas.Count > 0)
                        {
                            var lines = new StringBuilder();
                            for (int i = 0; i < iface.MethodRvas.Count; i++)
                            {
                                uint rva = iface.MethodRvas[i];
                                string label = exportRvaToName.TryGetValue(rva, out var name)
                                    ? name
                                    : $"sub_{rva:X}";
                                lines.AppendLine($"  [{i,3}]  RVA 0x{rva:X8}   {label}");
                            }
                            findings.Add(new Finding(
                                "  Methods",
                                $"{iface.MethodRvas.Count} stub address(es)",
                                lines.ToString().TrimEnd()));
                        }
                    }
                }

                // --- 2b. All named exports (not just COM ones) ---
                if (exports.Count > 0)
                {
                    var nonComExports = exports.Where(e => !ComServerExports.Contains(e.Name)).ToList();
                    int show = Math.Min(50, exports.Count);
                    var detail = new StringBuilder();
                    foreach (var e in exports.Take(show))
                    {
                        bool isCom = ComServerExports.Contains(e.Name);
                        detail.Append($"  {(isCom ? "*" : " ")} {e.Name,-48}  RVA 0x{e.Rva:X8}\n");
                    }
                    if (exports.Count > show)
                        detail.Append($"  ... and {exports.Count - show} more\n");
                    findings.Add(new Finding(
                        "All named exports",
                        exports.Count.ToString(),
                        detail.ToString().TrimEnd() + "\n\n* = COM in-process server entry point"));
                }

                // --- 3. Embedded GUIDs (potential CLSIDs / IIDs / interface UUIDs) ---
                var guids = ScanGuidStrings(context.Bytes);
                if (guids.Count > 0)
                {
                    int show = Math.Min(50, guids.Count);
                    var detail = new StringBuilder();
                    for (int i = 0; i < show; i++)
                        detail.AppendLine($"  {guids[i]}");
                    if (guids.Count > show)
                        detail.AppendLine($"  ... and {guids.Count - show} more");

                    findings.Add(new Finding(
                        "Embedded GUIDs",
                        guids.Count.ToString(),
                        detail.ToString().TrimEnd(),
                        Severity.Info));
                }

                // --- 4. TypeLib resources ---
                bool hasTypeLib = HasTypeLibResource(pe, context.Bytes);
                if (hasTypeLib)
                {
                    findings.Add(new Finding(
                        "Type library",
                        "Embedded TYPELIB resource (COM type information)",
                        null,
                        Severity.Info));
                }

                // --- 5. Headline ---
                string headline = (isComServer, comCalls.Count > 0, rpcServer, rpcClient) switch
                {
                    (true,  _,    true,  _)     => "COM in-process server + RPC server",
                    (true,  _,    false, true)  => "COM in-process server + RPC client",
                    (true,  _,    false, false) => "COM in-process server",
                    (false, true, true,  _)     => "COM client + RPC server",
                    (false, true, false, true)  => "COM client + RPC client",
                    (false, true, false, false) => "COM client",
                    (false, false, true, _)     => "RPC server",
                    (false, false, false, true) => "RPC client",
                    _                           => "No COM/RPC indicators detected",
                };

                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = headline,
                    Findings = findings,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Interfaces inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    public sealed record RpcServerInterface(
        string Uuid,
        ushort MajorVersion,
        ushort MinorVersion,
        int FileOffset,
        string TransferSyntax,
        int StructLength,
        int MethodCount,
        IReadOnlyList<uint> MethodRvas);

    // RPC NDR transfer-syntax UUIDs as they appear in memory (mixed endianness).
    // NDR20  = 8a885d04-1ceb-11c9-9fe8-08002b104860  → 04 5D 88 8A EB 1C C9 11 9F E8 08 00 2B 10 48 60
    // NDR64  = 71710533-beba-4937-8319-b5dbef9ccc36  → 33 05 71 71 BA BE 37 49 83 19 B5 DB EF 9C CC 36
    private static readonly byte[] Ndr20Bytes = new byte[]
    {
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
        0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
    };
    private static readonly byte[] Ndr64Bytes = new byte[]
    {
        0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49,
        0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36,
    };

    /// <summary>
    /// Scan the binary for RPC_SERVER_INTERFACE structs. The struct layout begins
    ///   uint32 Length
    ///   GUID   InterfaceId.SyntaxGUID
    ///   uint16 InterfaceId.MajorVersion
    ///   uint16 InterfaceId.MinorVersion
    ///   GUID   TransferSyntax.SyntaxGUID   ← we scan for the NDR20/NDR64 UUID here
    /// We anchor on the well-known transfer-syntax UUID, then walk back 24 bytes
    /// to the struct start and read the InterfaceId.
    /// </summary>
    private static List<RpcServerInterface> FindRpcServerInterfaces(byte[] bytes, PEReader pe, ulong imageBase, bool pe32Plus)
    {
        var hits = new List<RpcServerInterface>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var span = (ReadOnlySpan<byte>)bytes;
        int dispatchTableOffsetInStruct = pe32Plus ? 48 : 44;
        // RPC_SERVER_INTERFACE / RPC_CLIENT_INTERFACE share the same layout and size.
        int expectedLength = pe32Plus ? 96 : 68;

        // Pre-compute executable section ranges (RVA + size) so we can validate method pointers.
        var execSections = pe.PEHeaders.SectionHeaders
            .Where(s => (s.SectionCharacteristics & SectionCharacteristics.MemExecute) != 0)
            .Select(s => (Start: (uint)s.VirtualAddress, End: (uint)(s.VirtualAddress + s.VirtualSize)))
            .ToArray();
        bool RvaIsExecutable(uint rva)
        {
            if (rva == 0) return false;
            foreach (var (start, end) in execSections)
                if (rva >= start && rva < end) return true;
            return false;
        }

        foreach (var (needle, name) in new[] { (Ndr20Bytes, "NDR20"), (Ndr64Bytes, "NDR64") })
        {
            int from = 0;
            while (from <= span.Length - needle.Length)
            {
                int idx = span.Slice(from).IndexOf((ReadOnlySpan<byte>)needle);
                if (idx < 0) break;
                int abs = from + idx;
                from = abs + 1;

                int structStart = abs - 24;
                if (structStart < 0 || structStart + expectedLength > bytes.Length) continue;

                int length = BitConverter.ToInt32(bytes, structStart);
                // Exact match per bitness — drops misaligned hits and stray NDR UUIDs.
                if (length != expectedLength) continue;

                var uuid = new Guid(bytes.AsSpan(structStart + 4, 16));
                if (uuid == Guid.Empty) continue;
                ushort major = BitConverter.ToUInt16(bytes, structStart + 20);
                ushort minor = BitConverter.ToUInt16(bytes, structStart + 22);
                if (major > 100 || minor > 1000) continue;

                string key = $"{uuid:N}_{major}.{minor}";
                if (!seen.Add(key)) continue;

                // Resolve DispatchTable → DispatchTableCount + function pointer array.
                int methodCount = 0;
                List<uint> methodRvas = new();
                ulong dispatchTableVa = pe32Plus
                    ? BitConverter.ToUInt64(bytes, structStart + dispatchTableOffsetInStruct)
                    : BitConverter.ToUInt32(bytes, structStart + dispatchTableOffsetInStruct);
                var (count, fnsArrayVa) = ReadDispatchTable(bytes, pe, imageBase, pe32Plus, dispatchTableVa);
                if (count > 0 && count <= 256)
                {
                    var allRvas = ReadFunctionPointers(bytes, pe, imageBase, pe32Plus, fnsArrayVa, count);
                    // Every method pointer must resolve into an executable section. Otherwise the
                    // DispatchTable likely belongs to a client-side interface (often null) or we hit
                    // a false-positive struct that happens to embed the NDR UUID.
                    bool allValid = allRvas.Count == count && allRvas.All(RvaIsExecutable);
                    if (allValid)
                    {
                        methodCount = count;
                        methodRvas = allRvas;
                    }
                }

                // Drop entries with no validated methods — they're almost always client-side
                // RPC_CLIENT_INTERFACE structs, not exposed server interfaces.
                if (methodCount == 0) continue;

                hits.Add(new RpcServerInterface(
                    uuid.ToString("B").ToUpperInvariant(),
                    major, minor, structStart, name, length,
                    methodCount, methodRvas));
            }
        }

        hits.Sort((a, b) => string.CompareOrdinal(a.Uuid, b.Uuid));
        return hits;
    }

    /// <summary>Read RPC_DISPATCH_TABLE { uint count; padding?; void** functions; } from the binary.</summary>
    private static (int Count, ulong FunctionsArrayVa) ReadDispatchTable(
        byte[] bytes, PEReader pe, ulong imageBase, bool pe32Plus, ulong dispatchTableVa)
    {
        if (dispatchTableVa == 0 || dispatchTableVa < imageBase) return (0, 0);
        long rva = (long)(dispatchTableVa - imageBase);
        if (rva <= 0 || rva > int.MaxValue) return (0, 0);
        if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int off)) return (0, 0);
        if (off + 16 > bytes.Length) return (0, 0);

        int count = BitConverter.ToInt32(bytes, off);
        ulong fns;
        if (pe32Plus)
        {
            // x64: count(4) + padding(4) + ptr(8)
            if (off + 12 > bytes.Length) return (0, 0);
            fns = BitConverter.ToUInt64(bytes, off + 8);
        }
        else
        {
            // x86: count(4) + ptr(4)
            fns = BitConverter.ToUInt32(bytes, off + 4);
        }
        return (count, fns);
    }

    /// <summary>Read N function pointers from an array. Returns RVAs (VA - imageBase).</summary>
    private static List<uint> ReadFunctionPointers(
        byte[] bytes, PEReader pe, ulong imageBase, bool pe32Plus, ulong arrayVa, int count)
    {
        var rvas = new List<uint>();
        if (count <= 0 || arrayVa == 0 || arrayVa < imageBase) return rvas;
        long rva = (long)(arrayVa - imageBase);
        if (rva <= 0 || rva > int.MaxValue) return rvas;
        if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int off)) return rvas;
        int ptrSize = pe32Plus ? 8 : 4;
        if (off + (long)count * ptrSize > bytes.Length) return rvas;
        for (int i = 0; i < count; i++)
        {
            ulong fnVa = pe32Plus
                ? BitConverter.ToUInt64(bytes, off + i * ptrSize)
                : BitConverter.ToUInt32(bytes, off + i * ptrSize);
            if (fnVa < imageBase) { rvas.Add(0); continue; }
            long fnRva = (long)(fnVa - imageBase);
            rvas.Add(fnRva is > 0 and <= uint.MaxValue ? (uint)fnRva : 0u);
        }
        return rvas;
    }

    private static List<string> ScanGuidStrings(byte[] bytes)
    {
        // Scan ASCII and UTF-16LE for {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} patterns. 38 chars.
        var hits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // ASCII pass — each pos a candidate.
        int span = 38;
        for (int i = 0; i <= bytes.Length - span; i++)
        {
            if (bytes[i] != (byte)'{' || bytes[i + 37] != (byte)'}') continue;
            if (IsGuidBody(bytes, i + 1, stride: 1))
                hits.Add(Encoding.ASCII.GetString(bytes, i, span));
        }

        // UTF-16LE pass.
        int wspan = span * 2;
        for (int i = 0; i + wspan <= bytes.Length; i += 2)
        {
            if (bytes[i] != (byte)'{' || bytes[i + 1] != 0) continue;
            if (bytes[i + 74] != (byte)'}' || bytes[i + 75] != 0) continue;
            if (IsGuidBody(bytes, i + 2, stride: 2))
                hits.Add(Encoding.Unicode.GetString(bytes, i, wspan));
        }
        return hits.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool IsGuidBody(byte[] b, int start, int stride)
    {
        // 8-4-4-4-12 hex; dashes at positions 8, 13, 18, 23 (0-indexed within body of 36 chars).
        ReadOnlySpan<int> dashes = stackalloc int[] { 8, 13, 18, 23 };
        for (int k = 0; k < 36; k++)
        {
            byte c = b[start + k * stride];
            // Reject if stride==2 and the high byte isn't zero.
            if (stride == 2 && b[start + k * stride + 1] != 0) return false;
            bool isDash = dashes.IndexOf(k) >= 0;
            if (isDash) { if (c != (byte)'-') return false; }
            else
            {
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) return false;
            }
        }
        return true;
    }

    private static bool HasTypeLibResource(PEReader pe, byte[] bytes)
    {
        var dir = pe.PEHeaders.PEHeader?.ResourceTableDirectory;
        if (dir is null || dir.Value.Size == 0) return false;
        if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int baseOff)) return false;

        if (baseOff + 16 > bytes.Length) return false;
        ushort namedCount = BitConverter.ToUInt16(bytes, baseOff + 12);
        ushort idCount    = BitConverter.ToUInt16(bytes, baseOff + 14);
        int entriesStart  = baseOff + 16;
        int total = namedCount + idCount;

        for (int i = 0; i < total; i++)
        {
            int entryOff = entriesStart + i * 8;
            if (entryOff + 8 > bytes.Length) return false;
            uint nameField = BitConverter.ToUInt32(bytes, entryOff);
            if ((nameField & 0x80000000) == 0)
            {
                // Numeric type id. RT_TYPELIB doesn't have a Windows-defined constant ID (it's "TYPELIB" named).
                continue;
            }
            int nameOffset = baseOff + (int)(nameField & 0x7FFFFFFF);
            if (nameOffset + 2 > bytes.Length) continue;
            ushort nameLen = BitConverter.ToUInt16(bytes, nameOffset);
            if (nameOffset + 2 + nameLen * 2 > bytes.Length) continue;
            string typeName = Encoding.Unicode.GetString(bytes, nameOffset + 2, nameLen * 2);
            if (typeName.Equals("TYPELIB", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    internal static List<(string Name, uint Rva)> ReadExports(byte[] bytes, PEReader pe)
    {
        var result = new List<(string, uint)>();
        var dir = pe.PEHeaders.PEHeader?.ExportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return result;
        if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int exportOff)) return result;

        uint numberOfNames = BitConverter.ToUInt32(bytes, exportOff + 24);
        uint addressOfFunctions = BitConverter.ToUInt32(bytes, exportOff + 28);
        uint addressOfNames = BitConverter.ToUInt32(bytes, exportOff + 32);
        uint addressOfNameOrdinals = BitConverter.ToUInt32(bytes, exportOff + 36);
        if (!LanguageInspector.TryRvaToOffset(pe, (int)addressOfNames, out int nameTableOff)) return result;
        if (!LanguageInspector.TryRvaToOffset(pe, (int)addressOfNameOrdinals, out int ordTableOff)) return result;
        if (!LanguageInspector.TryRvaToOffset(pe, (int)addressOfFunctions, out int fnTableOff)) return result;

        for (int i = 0; i < numberOfNames && i < 8192; i++)
        {
            int nameRvaOff = nameTableOff + i * 4;
            if (nameRvaOff + 4 > bytes.Length) break;
            uint nameRva = BitConverter.ToUInt32(bytes, nameRvaOff);
            if (!LanguageInspector.TryRvaToOffset(pe, (int)nameRva, out int nOff)) continue;
            int end = nOff;
            while (end < bytes.Length && bytes[end] != 0) end++;
            string fnName = Encoding.ASCII.GetString(bytes, nOff, end - nOff);

            int ordOff = ordTableOff + i * 2;
            if (ordOff + 2 > bytes.Length) continue;
            ushort ord = BitConverter.ToUInt16(bytes, ordOff);
            int fnRvaOff = fnTableOff + ord * 4;
            if (fnRvaOff + 4 > bytes.Length) continue;
            uint fnRva = BitConverter.ToUInt32(bytes, fnRvaOff);
            if (fnRva == 0) continue;
            result.Add((fnName, fnRva));
        }
        return result;
    }
}
