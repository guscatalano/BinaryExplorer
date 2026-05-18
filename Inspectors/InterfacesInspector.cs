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
