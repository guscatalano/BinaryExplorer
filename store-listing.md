# Microsoft Store listing — BinaryExplorer

Copy-paste content for the Partner Center submission, plus a privacy policy
draft and a pre-submission checklist.

---

## Product name

```
BinaryExplorer
```

## Tagline (one line)

```
Inspect any Windows binary — without running it.
```

## Category

Developer tools

## Pricing

Free

## App identity (Partner Center)

Reserved in Partner Center and applied to `Package.appxmanifest`:

| Field | Value |
| ----- | ----- |
| Package/Identity/Name | `GusCatalano.BinaryExplorer` |
| Package/Identity/Publisher | `CN=119E0257-3B74-437C-A728-AC7C50256853` |
| Package/Properties/PublisherDisplayName | `Gus Catalano` |
| Package Family Name | `GusCatalano.BinaryExplorer_hbnb01h0zx9vj` |
| Store ID | `9N4HTNCSTVMR` |
| Store URL | https://apps.microsoft.com/detail/9N4HTNCSTVMR |

## Description

```
Inspect any Windows binary — without running it.

BinaryExplorer is a fast, modern desktop tool for taking apart .exe, .dll, .sys,
.winmd, and .msi files. Drop a file in and it is broken down across more than two
dozen focused views, so you can answer questions in seconds: What language was it
written in? Is it signed, and by whom? What does it import? What can it actually
do? Where did it come from?

IDENTITY & PROVENANCE
• Language and runtime detection — native C/C++, C#/.NET, Go, Rust
• Authenticode signature and certificate-chain verification
• MD5, SHA-1, SHA-256, imphash, and Authenticode hashes
• Version info, Mark of the Web (download origin), and VirusTotal lookup

BUILD & STRUCTURE
• The MSVC "Rich header" compiler and linker fingerprint
• Debug info — PDB path, debug GUID, symbol-store hash
• Full PE structure: headers, sections, entropy, data directories
• A resource-tree browser with one-click extraction

BEHAVIOR
• Imports, exports, and grouped capability analysis — process injection,
  anti-debug, cryptography, networking, persistence, and more
• ETW providers, COM/RPC interfaces, and TLS callbacks
• Strings and IOCs — URLs, IPs, domains, registry paths, mutexes
• Packer detection — UPX, Themida, VMProtect, ASPack, and others

CODE
• An IDA-style x86/x64 disassembler with function detection and cross-references
• A C# decompiler for managed (.NET) assemblies
• An embedded-file scanner and extractor

AND MORE
• Side-by-side comparison of two binaries
• Markdown and JSON report export
• YARA scanning
• A built-in MCP server, so AI assistants can drive every inspector

BinaryExplorer is free and open source under the MIT license.
Source code: https://github.com/guscatalano/BinaryExplorer

It runs entirely on your machine. Nothing leaves your device unless you
explicitly use the optional VirusTotal lookup with your own API key.
```

## What's new in this version (1.0.1)

```
• The title bar now shows the name of the binary you are inspecting.
• Reliability and polish fixes.
```

## Product features (bulleted list — keep each under 200 characters)

```
Detect the language and runtime — native C/C++, C#/.NET, Go, Rust
Verify Authenticode signatures and certificate chains
Compute MD5, SHA-1, SHA-256, imphash, and Authenticode hashes
IDA-style x86/x64 disassembler with function detection and cross-references
C# decompiler for .NET assemblies
Inspect imports, exports, and grouped capability categories
Detect packers — UPX, Themida, VMProtect, ASPack, and more
Browse and extract PE resources
Find and extract files embedded inside a binary
Scan strings for URLs, IPs, domains, and other indicators of compromise
Decode the MSVC Rich header build fingerprint
Inspect Windows Installer (.msi) databases
Compare two binaries side by side
Export Markdown or JSON reports
Run YARA rules against a binary
Built-in MCP server for AI-assisted analysis
Runs fully offline — no account, no telemetry
```

## Search terms (max 7, each under 30 characters — not shown to users)

```
PE inspector
reverse engineering
disassembler
decompiler
malware analysis
binary analysis
developer tools
```

## Copyright and trademark info (optional)

```
© 2026 Gus Catalano. MIT licensed.
```

## Developed by

```
Gus Catalano
```

## System requirements

- Windows 10, version 1809 (build 17763) or later, and Windows 11
- Architectures: x64 and ARM64

---

## Privacy policy (host this and provide the URL in Partner Center)

A privacy policy URL is **required** because the app makes network connections.
Host the text below somewhere public (e.g. a page on guscatalano.dev) and enter
that URL in the submission.

```
BinaryExplorer — Privacy Policy

BinaryExplorer is a desktop application that inspects files on your computer.
It runs entirely on your device.

What we collect
None. BinaryExplorer has no user accounts, no analytics, and no telemetry. It
does not collect, store, or transmit any personal information.

Network activity
BinaryExplorer connects to the internet only when you explicitly use a feature
that requires it:
• VirusTotal lookup — if you enter your own VirusTotal API key and open the
  VirusTotal page, the SHA-256 hash of the file being inspected is sent to
  virustotal.com to retrieve its detection report. File contents are never
  uploaded.
• YARA — the first time you use the YARA page, the app may download the yara.exe
  scanner from its official GitHub releases.
• The optional built-in MCP server listens only on localhost and is off by
  default.

The contents of the files you inspect never leave your device, apart from the
SHA-256 hash described above.

Contact: https://guscatalano.dev/

Last updated: 2026-05-20
```

---

## Screenshots

The Store accepts 1–10 desktop screenshots (PNG, at least 1366×768). Use the
images in `screenshots/` — for example:

| File | Suggested caption |
| ---- | ----------------- |
| `screenshots/01-overview.png`     | At-a-glance overview of any binary |
| `screenshots/09-dependencies.png` | Imports and exports, grouped by DLL |
| `screenshots/10-capabilities.png` | Capability analysis — what the binary can do |
| `screenshots/14-disassembly.png`  | IDA-style x86/x64 disassembly |
| `screenshots/25-decompile.png`    | C# decompilation of managed assemblies |
| `screenshots/24-compare.png`      | Compare two binaries side by side |

App icons / Store logos: the existing `Assets/` icon set covers the tile and
Store logo requirements.

---

## Age rating

Complete the IARC questionnaire in Partner Center. BinaryExplorer is a utility
with no objectionable content, so it should rate **Everyone / PEGI 3** — answer
"No" to all content questions; it does not share user-provided info, location,
or contacts.

---

## Pre-submission checklist

1. ~~Reserve the app name in Partner Center.~~ **Done** — see *App identity* above.
2. ~~Update `Package.appxmanifest` with the Store identity.~~ **Done** — the
   `Identity` Name/Publisher and `PublisherDisplayName` now match the reserved
   app. The self-signed signing-cert subject in `build-packages.ps1` and
   `release.yml` was also updated to the new Publisher so sideload MSIX builds
   keep working.
3. **Remove the unused `systemAIModels` capability** from `Package.appxmanifest`
   unless the app actually uses Windows system AI models — declaring an unused
   restricted capability adds review friction. `runFullTrust` must stay; it is
   required for a full-trust Win32 desktop app and is expected for this app type.
4. **Privacy policy** — host the text above and enter the URL.
5. **Build the MSIX** with the Store identity (`build-packages.ps1` or the
   release workflow produces the package; the Store re-signs it, so the
   self-signed certificate is not used for Store distribution).
6. **Upload screenshots** from `screenshots/` and complete the age rating.
7. Set category to **Developer tools** and pricing to **Free**.
