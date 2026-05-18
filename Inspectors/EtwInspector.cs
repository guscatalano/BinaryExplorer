using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Xml.Linq;
using BinaryExplorer.Core;
using BinaryExplorer.Services;

namespace BinaryExplorer.Inspectors;

public sealed class EtwInspector : IBinaryInspector
{
    public string Name => "ETW";

    private static readonly string[] EtwImportDlls = new[] { "advapi32.dll", "ntdll.dll", "api-ms-win-eventing" };
    private static readonly string[] EtwRuntimeMarkers = new[]
    {
        "EventRegister", "EventUnregister", "EventWrite", "EventWriteEx",
        "EventWriteTransfer", "EventWriteString", "EventActivityIdControl",
        "EtwEventRegister", "EtwEventWrite", "EtwRegister",
    };

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var stream = context.OpenStream();
                using var pe = new PEReader(stream);

                var usesEtwImports = DetectEtwImports(pe, out var importMatches);
                if (usesEtwImports)
                {
                    findings.Add(new Finding(
                        "Runtime ETW",
                        "Yes",
                        "Imports: " + string.Join(", ", importMatches)));
                }
                else
                {
                    findings.Add(new Finding("Runtime ETW", "No (no EventRegister/EventWrite* imports detected)"));
                }

                var manifested = TryReadManifestedProviders(pe);
                if (manifested.Count > 0)
                {
                    findings.Add(new Finding(
                        "Manifested providers (WEVT_TEMPLATE)",
                        manifested.Count.ToString()));
                    foreach (var p in manifested)
                    {
                        findings.Add(new Finding(
                            p.Name ?? $"Provider {p.Guid}",
                            p.Guid.ToString(),
                            $"Events: {p.EventCount}"));
                    }
                }

                // Experimental: native GUID+pointer scan (byte-pattern match, may have false positives).
                // Off by default; toggle in Settings.
                List<NativeProvider> dedupNative = new();
                if (Settings.EnableExperimentalEtwScan)
                {
                    var nativeProviders = ScanNativeProviders(pe);
                    dedupNative = nativeProviders.Where(p => !manifested.Any(m => m.Guid == p.Guid)).ToList();
                    findings.Add(new Finding(
                        "[Experimental] Native scan providers",
                        dedupNative.Count.ToString(),
                        "Byte-pattern scan (GUID + pointer-to-string) in .rdata/.data. May include false positives. Toggle in Settings."));
                    foreach (var p in dedupNative)
                    {
                        findings.Add(new Finding($"  • {p.Name}", p.Guid.ToString(), $"Section: {p.Section}", Severity.Warning));
                    }
                }
                else
                {
                    findings.Add(new Finding(
                        "Native scan (experimental)",
                        "Disabled",
                        "Enable in Settings to scan .rdata/.data for TraceLogging provider GUIDs. Heuristic — may have false positives."));
                }

                var managedManifest = TryReadManagedManifestProviders(pe);
                if (managedManifest.Count > 0)
                {
                    findings.Add(new Finding(
                        "Managed manifest providers",
                        managedManifest.Count.ToString(),
                        "Extracted from embedded .manifest XML resources in the managed assembly."));
                    foreach (var p in managedManifest)
                    {
                        findings.Add(new Finding(p.Name ?? "(unnamed)", p.Guid?.ToString() ?? ""));
                    }
                }

                var wevtutil = TryWevtutil(context.Path);
                if (wevtutil.Providers.Count > 0)
                {
                    findings.Add(new Finding(
                        "wevtutil.exe providers",
                        wevtutil.Providers.Count.ToString(),
                        "Reported by `wevtutil im` on the binary."));
                    foreach (var p in wevtutil.Providers)
                    {
                        findings.Add(new Finding(p.Name ?? "(unnamed)", p.Guid?.ToString() ?? ""));
                    }
                }
                else if (wevtutil.Tried)
                {
                    findings.Add(new Finding("wevtutil.exe", "(no providers reported)"));
                }

                int totalProviders = manifested.Count + dedupNative.Count + managedManifest.Count + wevtutil.Providers.Count;
                string headline = (usesEtwImports, totalProviders) switch
                {
                    (_, > 0) when usesEtwImports => $"ETW: {totalProviders} provider(s) + runtime",
                    (_, > 0) => $"ETW: {totalProviders} provider(s)",
                    (true, 0) => "ETW: runtime imports but no providers found",
                    _ => "ETW: none detected",
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
                    Headline = "ETW inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static bool DetectEtwImports(PEReader pe, out List<string> matches)
    {
        matches = new List<string>();
        var dlls = LanguageInspector.ReadImportedDllNames(pe);
        bool hasEtwDll = dlls.Any(d => EtwImportDlls.Any(e => d.StartsWith(e, StringComparison.OrdinalIgnoreCase)));
        if (!hasEtwDll) return false;

        var image = pe.GetEntireImage().GetContent();
        foreach (var marker in EtwRuntimeMarkers)
        {
            if (ContainsAscii(image.AsSpan(), marker))
                matches.Add(marker);
        }
        return matches.Count > 0;
    }

    private static bool ContainsAscii(ReadOnlySpan<byte> haystack, string needle)
    {
        Span<byte> n = stackalloc byte[needle.Length];
        for (int i = 0; i < needle.Length; i++) n[i] = (byte)needle[i];
        for (int i = 0; i + n.Length <= haystack.Length; i++)
        {
            if (haystack.Slice(i, n.Length).SequenceEqual(n)) return true;
        }
        return false;
    }

    public record ManifestedProvider(Guid Guid, string? Name, int EventCount);
    public record NativeProvider(Guid Guid, string Name, string Section);
    public record ManagedManifestProvider(string? Name, Guid? Guid);

    // ===== Native GUID+pointer scan, ported from findneedle's EtwNativeProviderScanner =====
    private static List<NativeProvider> ScanNativeProviders(PEReader pe)
    {
        var result = new List<NativeProvider>();
        var imageImm = pe.GetEntireImage().GetContent();
        var image = imageImm.AsSpan();

        bool pe32Plus = pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus;
        int pointerSize = pe32Plus ? 8 : 4;

        // Collect candidate sections — .rdata and .data hold strings + globals where TraceLogging providers live.
        var candidateSections = new List<(string Name, int Va, int FileOff, int Size)>();
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            if (s.Name == ".rdata" || s.Name == ".data" || s.Name == ".text")
                candidateSections.Add((s.Name, s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData));
        }
        if (candidateSections.Count == 0) return result;

        var seen = new HashSet<Guid>();
        foreach (var (secName, secVa, secOff, secSize) in candidateSections)
        {
            if (secOff + secSize > image.Length) continue;
            var data = image.Slice(secOff, secSize);
            int limit = data.Length - 16 - pointerSize;
            for (int i = 0; i < limit; i++)
            {
                var guidBytes = data.Slice(i, 16);
                if (IsGarbageGuid(guidBytes)) continue;
                var guid = new Guid(guidBytes);

                ulong ptr = pointerSize == 8
                    ? BitConverter.ToUInt64(data.Slice(i + 16, 8))
                    : BitConverter.ToUInt32(data.Slice(i + 16, 4));
                if (ptr == 0) continue;

                // Pointer is a runtime VA: imageBase + RVA. Subtract image base to get RVA.
                ulong imageBase = pe.PEHeaders.PEHeader?.ImageBase ?? 0;
                if (ptr < imageBase) continue;
                long rva = (long)(ptr - imageBase);
                if (rva <= 0 || rva > int.MaxValue) continue;

                if (!LanguageInspector.TryRvaToOffset(pe, (int)rva, out int strOff)) continue;

                var name = TryReadProviderName(image, strOff);
                if (name is null) continue;
                if (!seen.Add(guid)) continue;
                result.Add(new NativeProvider(guid, name, secName));
            }
        }
        return result;
    }

    private static bool IsGarbageGuid(ReadOnlySpan<byte> bytes)
    {
        // Reject all-zero and all-0xFF.
        bool allZero = true, allFF = true;
        for (int i = 0; i < 16; i++)
        {
            if (bytes[i] != 0x00) allZero = false;
            if (bytes[i] != 0xFF) allFF = false;
            if (!allZero && !allFF) return false;
        }
        return true;
    }

    private static string? TryReadProviderName(ReadOnlySpan<byte> image, int offset)
    {
        // Try ASCII first
        int asciiLen = 0;
        while (offset + asciiLen < image.Length && asciiLen < 96
               && image[offset + asciiLen] >= 0x20 && image[offset + asciiLen] < 0x7F)
            asciiLen++;
        bool asciiTerm = offset + asciiLen < image.Length && image[offset + asciiLen] == 0;
        if (asciiLen >= 4 && asciiTerm)
        {
            var s = Encoding.ASCII.GetString(image.Slice(offset, asciiLen));
            if (LooksLikeProviderName(s)) return s;
        }

        // Try UTF-16LE
        int wideLen = 0;
        while (offset + wideLen * 2 + 1 < image.Length && wideLen < 96
               && image[offset + wideLen * 2 + 1] == 0
               && image[offset + wideLen * 2] >= 0x20
               && image[offset + wideLen * 2] < 0x7F)
            wideLen++;
        bool wideTerm = offset + wideLen * 2 + 1 < image.Length
                        && image[offset + wideLen * 2] == 0
                        && image[offset + wideLen * 2 + 1] == 0;
        if (wideLen >= 4 && wideTerm)
        {
            var s = Encoding.Unicode.GetString(image.Slice(offset, wideLen * 2));
            if (LooksLikeProviderName(s)) return s;
        }
        return null;
    }

    private static bool LooksLikeProviderName(string s)
    {
        // Provider names: letters/digits/dash/dot/underscore. Must contain at least one letter.
        bool hasLetter = false;
        foreach (var c in s)
        {
            if (char.IsLetterOrDigit(c) || c == '-' || c == '.' || c == '_' || c == ' ')
            {
                if (char.IsLetter(c)) hasLetter = true;
                continue;
            }
            return false;
        }
        return hasLetter;
    }

    // ===== Managed .manifest XML resource scan =====
    private static List<ManagedManifestProvider> TryReadManagedManifestProviders(PEReader pe)
    {
        var providers = new List<ManagedManifestProvider>();
        if (!pe.HasMetadata) return providers;
        try
        {
            var md = pe.GetMetadataReader();
            foreach (var handle in md.ManifestResources)
            {
                var res = md.GetManifestResource(handle);
                var name = md.GetString(res.Name);
                if (!name.EndsWith(".manifest", StringComparison.OrdinalIgnoreCase)) continue;
                if (!res.Implementation.IsNil) continue; // External resource, skip
                // Embedded resource: read from PE resources section.
                var resourcesDir = pe.PEHeaders.CorHeader?.ResourcesDirectory;
                if (resourcesDir is null) continue;
                if (!LanguageInspector.TryRvaToOffset(pe, resourcesDir.Value.RelativeVirtualAddress, out int baseOff))
                    continue;
                var imageImm = pe.GetEntireImage().GetContent();
                var image = imageImm.AsSpan();
                long resOffset = baseOff + (long)res.Offset;
                if (resOffset + 4 > image.Length) continue;
                uint size = BitConverter.ToUInt32(image.Slice((int)resOffset, 4));
                if (resOffset + 4 + size > image.Length) continue;
                var xmlBytes = image.Slice((int)resOffset + 4, (int)size);
                string xml = Encoding.UTF8.GetString(xmlBytes);
                foreach (var (n, g) in ParseManifestXml(xml))
                    providers.Add(new ManagedManifestProvider(n, g));
            }
        }
        catch { /* best effort */ }
        return providers;
    }

    private static IEnumerable<(string? Name, Guid? Guid)> ParseManifestXml(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) yield break;
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch { yield break; }
        foreach (var el in doc.Descendants())
        {
            if (!el.Name.LocalName.Equals("provider", StringComparison.OrdinalIgnoreCase)) continue;
            var nameAttr = el.Attribute("name")?.Value;
            var guidAttr = el.Attribute("guid")?.Value;
            Guid? g = null;
            if (!string.IsNullOrWhiteSpace(guidAttr) && Guid.TryParse(guidAttr, out var parsed)) g = parsed;
            yield return (nameAttr, g);
        }
    }

    // ===== wevtutil fallback =====
    public sealed class WevtutilResult
    {
        public bool Tried;
        public List<(string? Name, Guid? Guid)> Providers = new();
    }

    private static WevtutilResult TryWevtutil(string binaryPath)
    {
        var r = new WevtutilResult();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil.exe",
                Arguments = $"gp /e:true \"{binaryPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return r;
            r.Tried = true;
            string stdout = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(3000))
            {
                try { proc.Kill(); } catch { }
                return r;
            }
            if (proc.ExitCode != 0) return r;
            // 'wevtutil gp' on a binary won't usually accept a path. Fall back to 'im' which validates the manifest.
            // Easier: scan output for "provider" lines with GUID syntax.
            foreach (var line in stdout.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("provider", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split(':', 2);
                    if (parts.Length == 2) r.Providers.Add((parts[1].Trim(), null));
                }
            }
        }
        catch { /* tool missing or denied — fine */ }
        return r;
    }

    // ===== WEVT_TEMPLATE CRIM parser (unchanged) =====
    private static List<ManifestedProvider> TryReadManifestedProviders(PEReader pe)
    {
        var result = new List<ManifestedProvider>();
        var blob = FindWevtTemplateBlob(pe);
        if (blob is null) return result;

        var span = blob.AsSpan();
        if (span.Length < 16) return result;
        if (!(span[0] == (byte)'C' && span[1] == (byte)'R' && span[2] == (byte)'I' && span[3] == (byte)'M'))
            return result;

        uint numProviders = BitConverter.ToUInt32(span.Slice(12, 4));
        int cursor = 16;
        for (int i = 0; i < numProviders; i++)
        {
            if (cursor + 20 > span.Length) break;
            var guid = new Guid(span.Slice(cursor, 16));
            uint offsetToProvider = BitConverter.ToUInt32(span.Slice(cursor + 16, 4));
            cursor += 20;

            int eventCount = 0;
            string? name = null;
            if (offsetToProvider + 16 <= span.Length)
            {
                var p = span.Slice((int)offsetToProvider);
                if (p[0] == (byte)'W' && p[1] == (byte)'E' && p[2] == (byte)'V' && p[3] == (byte)'T')
                {
                    uint numOffsets = BitConverter.ToUInt32(p.Slice(12, 4));
                    int listCursor = 16;
                    for (int j = 0; j < numOffsets && listCursor + 8 <= p.Length; j++)
                    {
                        uint type = BitConverter.ToUInt32(p.Slice(listCursor, 4));
                        uint subOffset = BitConverter.ToUInt32(p.Slice(listCursor + 4, 4));
                        listCursor += 8;
                        if (type == 1 && subOffset + 8 <= p.Length)
                        {
                            var ev = p.Slice((int)subOffset);
                            if (ev.Length >= 16 && ev[0] == (byte)'E' && ev[1] == (byte)'V' && ev[2] == (byte)'N' && ev[3] == (byte)'T')
                            {
                                eventCount = (int)BitConverter.ToUInt32(ev.Slice(8, 4));
                            }
                        }
                    }
                }
            }

            result.Add(new ManifestedProvider(guid, name, eventCount));
        }
        return result;
    }

    private static byte[]? FindWevtTemplateBlob(PEReader pe)
    {
        var dir = pe.PEHeaders.PEHeader?.ResourceTableDirectory;
        if (dir is null || dir.Value.Size == 0) return null;
        int rva = dir.Value.RelativeVirtualAddress;
        if (!LanguageInspector.TryRvaToOffset(pe, rva, out int baseOffset)) return null;

        var image = pe.GetEntireImage().GetContent().ToArray();

        if (baseOffset + 16 > image.Length) return null;
        ushort namedCount = BitConverter.ToUInt16(image, baseOffset + 12);
        ushort idCount = BitConverter.ToUInt16(image, baseOffset + 14);
        int entriesStart = baseOffset + 16;

        for (int i = 0; i < namedCount; i++)
        {
            int entryOff = entriesStart + i * 8;
            uint nameField = BitConverter.ToUInt32(image, entryOff);
            uint dataField = BitConverter.ToUInt32(image, entryOff + 4);
            if ((nameField & 0x80000000) == 0) continue;
            int nameOffset = baseOffset + (int)(nameField & 0x7FFFFFFF);
            if (nameOffset + 2 > image.Length) continue;
            ushort nameLen = BitConverter.ToUInt16(image, nameOffset);
            if (nameOffset + 2 + nameLen * 2 > image.Length) continue;
            string typeName = Encoding.Unicode.GetString(image, nameOffset + 2, nameLen * 2);
            if (!typeName.Equals("WEVT_TEMPLATE", StringComparison.OrdinalIgnoreCase)) continue;

            if ((dataField & 0x80000000) == 0) continue;
            int nameDirOff = baseOffset + (int)(dataField & 0x7FFFFFFF);
            return ReadFirstLeaf(image, baseOffset, nameDirOff, pe);
        }
        _ = idCount;
        return null;
    }

    private static byte[]? ReadFirstLeaf(byte[] image, int resBase, int dirOff, PEReader pe)
    {
        if (dirOff + 16 > image.Length) return null;
        ushort named = BitConverter.ToUInt16(image, dirOff + 12);
        ushort ids = BitConverter.ToUInt16(image, dirOff + 14);
        int total = named + ids;
        int entriesStart = dirOff + 16;
        for (int i = 0; i < total; i++)
        {
            int entryOff = entriesStart + i * 8;
            uint dataField = BitConverter.ToUInt32(image, entryOff + 4);
            if ((dataField & 0x80000000) != 0)
            {
                int childOff = resBase + (int)(dataField & 0x7FFFFFFF);
                var sub = ReadFirstLeaf(image, resBase, childOff, pe);
                if (sub is not null) return sub;
            }
            else
            {
                int leafOff = resBase + (int)dataField;
                if (leafOff + 16 > image.Length) return null;
                uint dataRva = BitConverter.ToUInt32(image, leafOff);
                uint dataSize = BitConverter.ToUInt32(image, leafOff + 4);
                if (!LanguageInspector.TryRvaToOffset(pe, (int)dataRva, out int dataOff)) return null;
                if (dataOff + dataSize > image.Length) return null;
                var buf = new byte[dataSize];
                Array.Copy(image, dataOff, buf, 0, (int)dataSize);
                return buf;
            }
        }
        return null;
    }
}
