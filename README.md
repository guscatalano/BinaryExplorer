# BinaryExplorer

A WinUI3 desktop app for inspecting Windows binaries (.exe / .dll / .sys / .winmd) without running them — language detection, signatures, hashes, imports, capabilities, ETW providers, strings/IOCs, packing, resources, disassembly, decompilation, embedded files, and more. Includes an MCP server so AI clients can drive the same inspectors.

## What's in here

| Area | Inspectors |
| ---- | ---------- |
| Identity | Language detection, Version info, Authenticode signature, Hashes (incl. imphash + Authenticode SHA-256) |
| Build | Rich header (MSVC compiler fingerprint), Debug info (PDB path + GUID + symstore hash) |
| Behavior | ETW providers (manifested + TraceLogging GUID scan + `wevtutil`), Dependencies (imports/exports), Capabilities (Process Injection, Anti-Debug, Crypto, Network, etc.), Strings & IOCs (URLs, IPs, domains, registry paths, mutexes…), TLS callbacks |
| Code | C# decompilation (ICSharpCode.Decompiler), x86/x64 disassembly (Iced) with function detection, local labels, xrefs, hyperlinkable jumps, back/forward history |
| Structure | PE headers, PE resources tree, Packing (Shannon entropy + UPX/ASPack/Themida/VMProtect/Enigma/PEtite/MPRESS/PECompact/NsPack/FSG), Embedded file scan, Hex view |
| Provenance | Mark of the Web (Zone.Identifier ADS + full ADS enumeration), VirusTotal (SHA-256 lookup), YARA (auto-download or shell out to `yara.exe`) |
| Tools | Side-by-side compare, Markdown / JSON report export, Drag-and-drop loading |

The whole-binary analyzer (`Analysis/PeAnalysis.cs`) does a linear sweep of executable sections in `Iced` to find every `call` target and build an xrefs map. That feeds the IDA-style **Disassembly** page with a function sidebar, search filter, and clickable jump annotations.

## MCP server

`Settings → MCP server` starts an HTTP MCP server **inside** the WinUI3 process via `HttpListener`. Tools are wired straight to the existing inspector pipeline. Sample configs for VS Code Copilot, Claude Code, and curl are right there with one-click copy.

A separate sibling console project `BinaryExplorer.Mcp/` builds `be-mcp.exe`, an MCP server with the same tools over stdio — useful for Claude Desktop and any other stdio-only MCP client.

Tools exposed (HTTP):
- `inspect(path, inspector?)` — all inspectors or one by name; preview-truncated for the "all" case
- `list_inspectors()` — returns every inspector name
- `disassemble(path, rva, count?, stopAtRet?)` — x86/x64 native disassembly at an RVA
- `read_bytes(path, offset, length?)` — hex+ASCII dump

## Building

Requires .NET 10 SDK and Windows 10.0.17763 or newer.

```pwsh
dotnet build -p:Platform=x64
dotnet run   -p:Platform=x64
```

For the stdio MCP server:

```pwsh
dotnet build BinaryExplorer.Mcp -c Release
# produces BinaryExplorer.Mcp\bin\Release\net10.0\be-mcp.exe
```

## Layout

```
Analysis/             — whole-binary linear-sweep analyzer (functions + xrefs)
Assets/               — app icon set
BinaryExplorer.Mcp/   — sibling stdio MCP server project
Controls/             — reusable XAML controls (FindingsList, HexView, InspectorResultView)
Core/                 — Finding, InspectionResult, BinaryContext, EmbeddedHit, ComparisonRow
Inspectors/           — one class per inspector
Pages/                — one nav page per inspector + Overview / Compare / Settings
Services/             — AppState, BinaryLoader, ReportExporter, EmbeddedExtractor, YaraScanner,
                        YaraDownloader, Settings, Mcp/{McpHttpServer,Dispatcher,Tools}
tools/                — Generate-Icons.ps1 (Powershell icon renderer)
```

## License

MIT — see [`LICENSE`](LICENSE).
