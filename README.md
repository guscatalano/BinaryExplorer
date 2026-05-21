# BinaryExplorer

A WinUI3 desktop app for inspecting Windows binaries (.exe / .dll / .sys / .winmd / .msi) without running them — language detection, signatures, hashes, imports, capabilities, ETW providers, strings/IOCs, packing, resources, disassembly, decompilation, embedded files, and more. Includes an MCP server so AI clients can drive the same inspectors.

![BinaryExplorer](screenshots/01-overview.png)

## Download

Grab the latest build from the [Releases page](https://github.com/guscatalano/BinaryExplorer/releases) — x64 and ARM64:

- **MSI** (`BinaryExplorer-<arch>.msi`) — self-contained installer; no .NET runtime required.
- **MSIX** (`BinaryExplorer-<arch>-msix.zip`) — extract the zip and run `Install.ps1`. The package is signed with a self-signed certificate, so the script installs that certificate (into Trusted People), the runtime dependencies, and the app — prompting for elevation when needed.

## Pages

Every page is a focused view of one aspect of a binary. Open a file once on the **Overview** page (or drag-and-drop it) and every page below inspects it.

### Overview & Compare

| | |
| --- | --- |
| ![Overview](screenshots/01-overview.png)<br>**Overview** — At-a-glance headlines for the loaded binary (language, signature, ETW, PE metadata). Drag-and-drop to load; export a full Markdown or JSON report. | ![Compare](screenshots/24-compare.png)<br>**Compare** — Loads two binaries side by side and diffs any inspector's findings — spot exactly what changed between versions or how a sample differs from a known-good file. |

### Identity

| | |
| --- | --- |
| ![Language](screenshots/02-language.png)<br>**Language** — Detects the implementing language/runtime (native C/C++, C#/.NET, Go, Rust…) so you know which tooling and decompiler to reach for. | ![Version Info](screenshots/03-version-info.png)<br>**Version Info** — Reads the VERSIONINFO resource: product/file version, company, original filename, copyright — quick provenance and identity. |
| ![Signature](screenshots/04-signature.png)<br>**Signature** — Verifies the Authenticode signature: signer, certificate chain, timestamp — who vouched for the file and whether it is trusted. | ![Hashes](screenshots/05-hashes.png)<br>**Hashes** — MD5 / SHA-1 / SHA-256 plus imphash and the Authenticode hash — the identifiers you paste into threat-intel lookups and IOC lists. |

### Build

| | |
| --- | --- |
| ![Rich Header](screenshots/06-rich-header.png)<br>**Rich Header** — Decodes the undocumented MSVC "Rich" header — the exact compiler/linker toolset versions used to build the binary, a strong build fingerprint. | ![Debug Info](screenshots/07-debug-info.png)<br>**Debug Info** — Extracts the PDB path, debug GUID, and symbol-store hash — useful for symbolication and for spotting build-machine paths leaked into the PDB string. |

### Behavior

| | |
| --- | --- |
| ![ETW](screenshots/08-etw.png)<br>**ETW** — Enumerates the Event Tracing for Windows providers a binary registers (manifested + TraceLogging GUIDs) — what it can be observed emitting at runtime. | ![Dependencies](screenshots/09-dependencies.png)<br>**Dependencies** — The full import table grouped by DLL, plus exports — what OS surface the binary touches and what it offers to others. |
| ![Capabilities](screenshots/10-capabilities.png)<br>**Capabilities** — Buckets imports into behavior categories (Process Injection, Anti-Debug, Crypto, Network, Persistence…) — a fast read on what a binary is able to do. | ![COM / RPC](screenshots/11-com-rpc.png)<br>**COM / RPC** — Detects COM class/interface registrations and RPC interface UUIDs — the inter-process surface a binary exposes or consumes. |
| ![Strings & IOCs](screenshots/12-strings.png)<br>**Strings & IOCs** — Extracts ASCII/UTF-16 strings and highlights indicators: URLs, IPs, domains, registry paths, mutexes, file paths. | ![TLS Callbacks](screenshots/13-tls-callbacks.png)<br>**TLS Callbacks** — Lists TLS callback functions — code that runs before the entry point, a classic anti-analysis / early-execution hook. |

### Code

| | |
| --- | --- |
| ![Decompile](screenshots/25-decompile.png)<br>**Decompile (C#)** — Decompiles managed assemblies back to readable C# (ICSharpCode.Decompiler) — browse the type tree and read any method. | ![Disassembly](screenshots/14-disassembly.png)<br>**Disassembly** — IDA-style x86/x64 disassembly (Iced) with a discovered-function sidebar, cross-references, and clickable jumps. A whole-binary linear sweep finds every `call` target up front. |

### Structure

| | |
| --- | --- |
| ![PE](screenshots/15-pe.png)<br>**PE** — The raw PE structure: headers, sections (sizes, characteristics, entropy), and data directories. | ![Resources](screenshots/16-resources.png)<br>**Resources** — Walks the PE resource tree (icons, manifests, string tables, RT_RCDATA…) and lets you view or extract any entry. |
| ![Packing](screenshots/17-packing.png)<br>**Packing** — Shannon-entropy analysis plus signature matches for common packers (UPX, ASPack, Themida, VMProtect…) — flags obfuscated or compressed binaries. | ![Embedded Files](screenshots/18-embedded-files.png)<br>**Embedded Files** — Scans the binary for embedded files (archives, images, other PEs, documents…) and extracts them for further inspection. |
| ![MSI](screenshots/26-msi.png)<br>**MSI** — Opens a Windows Installer database and surfaces product info, the files it drops, registry writes, shortcuts, custom actions, and the feature tree. | ![Hex View](screenshots/19-hex-view.png)<br>**Hex View** — A raw hex / ASCII viewer with offset navigation and Ctrl+F search. |

### Provenance

| | |
| --- | --- |
| ![Mark of the Web](screenshots/20-mark-of-the-web.png)<br>**Mark of the Web** — Reads the Zone.Identifier alternate data stream (and enumerates all ADS) — shows whether the file was downloaded and from where. | ![VirusTotal](screenshots/21-virustotal.png)<br>**VirusTotal** — Looks up the file's SHA-256 on VirusTotal and shows the detection summary (needs a free API key). |
| ![YARA](screenshots/22-yara.png)<br>**YARA** — Runs YARA rules against the binary (bundled default rules plus your own), auto-downloading `yara.exe` if it isn't already present. | |

### Tools & Settings

| | |
| --- | --- |
| ![Tools](screenshots/23-tools.png)<br>**Tools** — On-demand utilities backed by the MCP tool surface: GUID lookup, cross-references, byte/string search, section dump, and Mermaid diagrams. | ![Settings](screenshots/27-settings.png)<br>**Settings** — MCP server controls with copy-paste client configs, VirusTotal key, experimental toggles, embedded-scan categories, and the About card. |
| ![About](screenshots/28-about.png)<br>**About** — Version and project links, at the bottom of Settings. | |

## MCP server

`Settings → MCP server` starts an HTTP MCP server **inside** the WinUI3 process via `HttpListener`. Tools are wired straight to the existing inspector pipeline — `inspect`, `disassemble`, `find_xrefs_ex`, `summarize_import_usage`, `get_call_graph_ex`, `architecture_evidence_pack`, and more. Set a current target once with `set_current_target` and the rest of the tools can omit the `path` argument. Sample configs for VS Code Copilot, Claude Code, and curl are right there with one-click copy.

## Building

Requires the .NET 10 SDK and Windows 10.0.17763 or newer.

```pwsh
dotnet build -p:Platform=x64
dotnet run   -p:Platform=x64
```

Helper scripts:

- `build-packages.ps1` — builds the signed MSIX and the WiX MSI locally.
- `take-screenshots.ps1` — captures the screenshots in this README automatically.

## Layout

```
Analysis/             — whole-binary linear-sweep analyzer (functions + xrefs)
Assets/               — app icon set
Controls/             — reusable XAML controls (FindingsList, HexView, InspectorResultView)
Core/                 — Finding, InspectionResult, BinaryContext, EmbeddedHit, ComparisonRow
Inspectors/           — one class per inspector
Pages/                — one nav page per inspector + Overview / Compare / Tools / Settings
Services/             — AppState, BinaryLoader, ReportExporter, GuidResolver, YaraScanner,
                        Settings, Mcp/{McpHttpServer,Dispatcher,Tools,Session}
installer/            — WiX v5 source for the MSI
.github/workflows/    — CI (build) and Release (MSIX + MSI) pipelines
```

## License

MIT — see [`LICENSE`](LICENSE).
