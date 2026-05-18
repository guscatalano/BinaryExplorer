using System.Reflection.PortableExecutable;
using BinaryExplorer.Core;
using BinaryExplorer.Services;

namespace BinaryExplorer.Inspectors;

public sealed class EmbeddedFilesInspector : IBinaryInspector
{
    public string Name => "Embedded";

    public enum SigCategory { Archives, Documents, Markup, Images, Media, Code, Data }

    private sealed record Signature(string Type, byte[] Magic, string Extension, SigCategory Category, string? Description = null);

    private static readonly Signature[] Signatures = new[]
    {
        new Signature("ZIP",      new byte[] { 0x50, 0x4B, 0x03, 0x04 }, ".zip", SigCategory.Archives, "ZIP local file header (also OOXML/JAR/APK/EPUB)"),
        new Signature("ZIP-eocd", new byte[] { 0x50, 0x4B, 0x05, 0x06 }, ".zip", SigCategory.Archives, "ZIP empty archive (EOCD marker)"),
        new Signature("ZIP-span", new byte[] { 0x50, 0x4B, 0x07, 0x08 }, ".zip", SigCategory.Archives, "ZIP spanned archive"),
        new Signature("GZIP",     new byte[] { 0x1F, 0x8B, 0x08 }, ".gz", SigCategory.Archives),
        new Signature("BZIP2",    new byte[] { 0x42, 0x5A, 0x68 }, ".bz2", SigCategory.Archives, "BZh"),
        new Signature("7-Zip",    new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, ".7z", SigCategory.Archives),
        new Signature("XZ",       new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, ".xz", SigCategory.Archives),
        new Signature("CAB",      new byte[] { 0x4D, 0x53, 0x43, 0x46 }, ".cab", SigCategory.Archives, "MSCF — Microsoft Cabinet"),
        new Signature("ZSTD",     new byte[] { 0x28, 0xB5, 0x2F, 0xFD }, ".zst", SigCategory.Archives),
        new Signature("RAR",      new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }, ".rar", SigCategory.Archives),
        new Signature("LZ4",      new byte[] { 0x04, 0x22, 0x4D, 0x18 }, ".lz4", SigCategory.Archives),
        new Signature("MSI/CFB",  new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, ".msi", SigCategory.Documents, "Compound Document (MSI / DOC / etc.)"),
        new Signature("PDF",      new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D }, ".pdf", SigCategory.Documents),
        new Signature("RTF",      new byte[] { 0x7B, 0x5C, 0x72, 0x74, 0x66 }, ".rtf", SigCategory.Documents),
        new Signature("XML",      new byte[] { 0x3C, 0x3F, 0x78, 0x6D, 0x6C }, ".xml", SigCategory.Markup),
        new Signature("PNG",      new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, ".png", SigCategory.Images),
        new Signature("JPEG",     new byte[] { 0xFF, 0xD8, 0xFF }, ".jpg", SigCategory.Images),
        new Signature("GIF87",    new byte[] { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 }, ".gif", SigCategory.Images),
        new Signature("GIF89",    new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 }, ".gif", SigCategory.Images),
        new Signature("ICO",      new byte[] { 0x00, 0x00, 0x01, 0x00 }, ".ico", SigCategory.Images),
        new Signature("CUR",      new byte[] { 0x00, 0x00, 0x02, 0x00 }, ".cur", SigCategory.Images),
        new Signature("BMP",      new byte[] { 0x42, 0x4D }, ".bmp", SigCategory.Images, "'BM' — high false-positive risk"),
        new Signature("RIFF",     new byte[] { 0x52, 0x49, 0x46, 0x46 }, ".bin", SigCategory.Media, "WAV/AVI/WebP — disambiguated by form type"),
        new Signature("MP4 ftyp", new byte[] { 0x66, 0x74, 0x79, 0x70 }, ".mp4", SigCategory.Media),
        new Signature("ELF",      new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, ".elf", SigCategory.Code),
        new Signature("Mach-O64", new byte[] { 0xCF, 0xFA, 0xED, 0xFE }, ".bin", SigCategory.Code),
        new Signature("Mach-O32", new byte[] { 0xCE, 0xFA, 0xED, 0xFE }, ".bin", SigCategory.Code),
        new Signature("Mach-O FAT", new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }, ".bin", SigCategory.Code),
        new Signature("PE / DOS", new byte[] { 0x4D, 0x5A }, ".bin", SigCategory.Code, "MZ — validated against PE header"),
        new Signature("SQLite",   System.Text.Encoding.ASCII.GetBytes("SQLite format 3\0"), ".sqlite", SigCategory.Data),
        new Signature("PEM cert", System.Text.Encoding.ASCII.GetBytes("-----BEGIN CERTIFICATE-----"), ".pem", SigCategory.Data),
        new Signature("PEM RSA",  System.Text.Encoding.ASCII.GetBytes("-----BEGIN RSA PRIVATE KEY-----"), ".pem", SigCategory.Data),
        new Signature("PEM key",  System.Text.Encoding.ASCII.GetBytes("-----BEGIN PRIVATE KEY-----"), ".pem", SigCategory.Data),
    };

    private static bool IsCategoryEnabled(SigCategory c) => c switch
    {
        SigCategory.Archives  => Settings.EmbeddedScanArchives,
        SigCategory.Documents => Settings.EmbeddedScanDocuments,
        SigCategory.Markup    => Settings.EmbeddedScanMarkup,
        SigCategory.Images    => Settings.EmbeddedScanImages,
        SigCategory.Media     => Settings.EmbeddedScanMedia,
        SigCategory.Code      => Settings.EmbeddedScanCode,
        SigCategory.Data      => Settings.EmbeddedScanData,
        _ => true,
    };

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            var hits = new List<EmbeddedHit>();
            try
            {
                var bytes = context.Bytes;
                var span = (ReadOnlySpan<byte>)bytes;

                var sections = ReadSectionMap(bytes);
                int endOfLastSection = sections.Count == 0
                    ? bytes.Length
                    : sections.Max(s => s.FileOffset + s.Size);

                var seenOffsets = new HashSet<long>();
                const int perTypeCap = 50;
                var perTypeCounts = new Dictionary<string, int>(StringComparer.Ordinal);

                foreach (var sig in Signatures)
                {
                    if (!IsCategoryEnabled(sig.Category)) continue;
                    int from = 0;
                    while (from <= span.Length - sig.Magic.Length)
                    {
                        int rel = span.Slice(from).IndexOf((ReadOnlySpan<byte>)sig.Magic);
                        if (rel < 0) break;
                        int abs = from + rel;
                        from = abs + 1;

                        // Skip the binary's own MZ at offset 0.
                        if (sig.Type == "PE / DOS" && abs == 0) continue;

                        // PE validation.
                        if (sig.Type == "PE / DOS")
                        {
                            if (abs + 0x40 > bytes.Length) continue;
                            int eLfanew = BitConverter.ToInt32(bytes, abs + 0x3C);
                            int peOff = abs + eLfanew;
                            if (eLfanew <= 0 || eLfanew > 0x4000 || peOff + 4 > bytes.Length) continue;
                            if (!(bytes[peOff] == 0x50 && bytes[peOff + 1] == 0x45 && bytes[peOff + 2] == 0 && bytes[peOff + 3] == 0))
                                continue;
                        }

                        // ZIP-eocd: only useful as the EOCD marker of a ZIP that started elsewhere; don't surface as a standalone hit.
                        if (sig.Type == "ZIP-eocd" || sig.Type == "ZIP-span") continue;

                        // Run structural validation BEFORE we do anything else with this hit.
                        if (!Validate(bytes, sig.Type, abs)) continue;

                        // RIFF disambiguation.
                        string typeLabel = sig.Type;
                        string extension = sig.Extension;
                        if (sig.Type == "RIFF" && abs + 12 <= bytes.Length)
                        {
                            var form = System.Text.Encoding.ASCII.GetString(bytes, abs + 8, 4);
                            (typeLabel, extension) = form switch
                            {
                                "WAVE" => ("WAV", ".wav"),
                                "AVI " => ("AVI", ".avi"),
                                "WEBP" => ("WebP", ".webp"),
                                _ => ($"RIFF:{form}", ".bin"),
                            };
                        }

                        // Cap per type to keep things sane.
                        perTypeCounts.TryGetValue(typeLabel, out int countForType);
                        if (countForType >= perTypeCap) continue;
                        if (!seenOffsets.Add(abs)) continue;

                        string section = LookupSection(sections, abs, endOfLastSection);
                        long? size = DetectSize(bytes, sig.Type, abs);
                        hits.Add(new EmbeddedHit(typeLabel, abs, size, section, extension, sig.Description));
                        perTypeCounts[typeLabel] = countForType + 1;
                    }
                }

                hits.Sort((a, b) => a.Offset.CompareTo(b.Offset));

                if (hits.Count == 0)
                {
                    findings.Add(new Finding("Scan result", "No embedded file signatures found"));
                }
                else
                {
                    findings.Add(new Finding(
                        "Hits",
                        hits.Count.ToString(),
                        $"Searched {bytes.Length:N0} bytes against {Signatures.Length} signatures."));

                    foreach (var grp in hits.GroupBy(h => h.Type).OrderByDescending(g => g.Count()))
                    {
                        var lines = grp.Select(h =>
                            $"  {h.OffsetHex}  size {h.SizeDisplay}  ({h.Section})").ToList();
                        findings.Add(new Finding(grp.Key, $"{grp.Count()} hit(s)", string.Join("\n", lines)));
                    }
                }

                string headline = hits.Count == 0
                    ? "No embedded files detected"
                    : $"{hits.GroupBy(h => h.Type).Count()} type(s), {hits.Count} total hit(s)";

                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = headline,
                    Findings = findings,
                    Payload = hits,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Embedded scan failed",
                    Findings = findings,
                    Payload = hits,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    // ===== Per-format structural validators (drop false positives where the magic alone is too short to be trustworthy). =====
    private static bool Validate(byte[] b, string type, int o)
    {
        try
        {
            return type switch
            {
                "JPEG" => ValidateJpeg(b, o),
                "ICO" => ValidateIco(b, o, 1),
                "CUR" => ValidateIco(b, o, 2),
                "BMP" => ValidateBmp(b, o),
                "RIFF" => ValidateRiff(b, o),
                "GZIP" => ValidateGzip(b, o),
                "MP4 ftyp" => ValidateFtyp(b, o),
                "RTF" => ValidateRtf(b, o),
                "XML" => ValidateXml(b, o),
                "PNG" => ValidatePng(b, o),
                "BZIP2" => ValidateBzip2(b, o),
                "CAB" => ValidateCab(b, o),
                "LZ4" => ValidateLz4(b, o),
                "ZSTD" => ValidateZstd(b, o),
                "ZIP" => ValidateZip(b, o),
                _ => true, // strong magics (>= 6 distinctive bytes) pass through
            };
        }
        catch { return false; }
    }

    private static bool ValidateJpeg(byte[] b, int o)
    {
        // Real JPEGs almost always start with one of:
        //   FF D8 FF E0 LL LL "JFIF\0"
        //   FF D8 FF E1 LL LL "Exif\0\0"  (or "http" for XMP)
        //   FF D8 FF EE LL LL "Adobe"
        //   FF D8 FF DB ...   (no app marker; require valid quantization-table walk)
        if (o + 12 > b.Length) return false;
        byte app = b[o + 3];
        switch (app)
        {
            case 0xE0:
                // Identifier starts at o+6 (after FF D8 FF E0 LL LL).
                return MatchAscii(b, o + 6, "JFIF\0") || MatchAscii(b, o + 6, "JFXX\0");
            case 0xE1:
                return MatchAscii(b, o + 6, "Exif\0") || MatchAscii(b, o + 6, "http://ns.adobe.com/xap/");
            case 0xEE:
                return MatchAscii(b, o + 6, "Adobe");
            case 0xDB:
            case 0xC0:
            case 0xC4:
                {
                    // No APP marker — walk markers strictly.
                    int i = o + 2;
                    int walked = 0;
                    while (i + 2 < b.Length && walked < 16)
                    {
                        if (b[i] != 0xFF) return false;
                        byte m = b[i + 1];
                        i += 2;
                        if (m == 0xFF) { i--; continue; }
                        if (m == 0x00) return false;
                        if (m == 0xD9) return walked >= 1; // EOI reached
                        if (m >= 0xD0 && m <= 0xD7) { walked++; continue; }
                        if (i + 2 > b.Length) return false;
                        int len = (b[i] << 8) | b[i + 1];
                        if (len < 2 || i + len > b.Length) return false;
                        i += len;
                        walked++;
                    }
                    return walked >= 3;
                }
            default:
                return false;
        }
    }

    private static bool MatchAscii(byte[] b, int o, string s)
    {
        if (o + s.Length > b.Length) return false;
        for (int i = 0; i < s.Length; i++)
            if (b[o + i] != (byte)s[i]) return false;
        return true;
    }

    private static bool ValidateIco(byte[] b, int o, int kind)
    {
        if (o + 22 > b.Length) return false;
        ushort res = BitConverter.ToUInt16(b, o);
        ushort type = BitConverter.ToUInt16(b, o + 2);
        ushort count = BitConverter.ToUInt16(b, o + 4);
        if (res != 0 || type != kind || count == 0 || count > 32) return false;
        int dirStart = o + 6;
        if (dirStart + count * 16 > b.Length) return false;
        for (int i = 0; i < count; i++)
        {
            int e = dirStart + i * 16;
            uint size = BitConverter.ToUInt32(b, e + 8);
            uint relOff = BitConverter.ToUInt32(b, e + 12);
            if (size == 0 || size > 10 * 1024 * 1024) return false;
            if (relOff < 6 + (uint)count * 16) return false;
            if ((long)o + relOff + size > b.Length) return false;
        }
        return true;
    }

    private static bool ValidateBmp(byte[] b, int o)
    {
        if (o + 30 > b.Length) return false;
        uint fileSize = BitConverter.ToUInt32(b, o + 2);
        if (fileSize < 54 || (long)o + fileSize > b.Length) return false;
        uint dibSize = BitConverter.ToUInt32(b, o + 14);
        return dibSize is 12 or 40 or 52 or 56 or 64 or 108 or 124;
    }

    private static bool ValidateRiff(byte[] b, int o)
    {
        if (o + 12 > b.Length) return false;
        uint size = BitConverter.ToUInt32(b, o + 4);
        if (size == 0xFFFFFFFF) return false;
        if ((long)o + 8 + size > b.Length) return false;
        for (int i = 0; i < 4; i++)
        {
            byte c = b[o + 8 + i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ';
            if (!ok) return false;
        }
        return true;
    }

    private static bool ValidateGzip(byte[] b, int o)
    {
        if (o + 10 > b.Length) return false;
        if (b[o + 2] != 0x08) return false; // CM=deflate
        byte flg = b[o + 3];
        if ((flg & 0xE0) != 0) return false; // reserved bits must be 0
        uint mtime = BitConverter.ToUInt32(b, o + 4);
        // 0 (unknown) or any value < year 2100.
        if (mtime != 0 && mtime > 4_102_444_800u) return false;
        byte xfl = b[o + 8];
        if (xfl != 0 && xfl != 2 && xfl != 4) return false;
        byte os = b[o + 9];
        if (os > 13 && os != 255) return false;
        // Strongest test: actually try to decompress the first byte.
        try
        {
            int remaining = b.Length - o;
            int probe = Math.Min(remaining, 64 * 1024);
            using var ms = new MemoryStream(b, o, probe, writable: false);
            using var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress);
            Span<byte> oneByte = stackalloc byte[1];
            return gz.Read(oneByte) >= 0; // 0 also acceptable (empty stream)
        }
        catch
        {
            return false;
        }
    }

    private static bool ValidateFtyp(byte[] b, int o)
    {
        // 'ftyp' is preceded by a 4-byte big-endian box size.
        if (o < 4 || o + 12 > b.Length) return false;
        uint boxSize = (uint)((b[o - 4] << 24) | (b[o - 3] << 16) | (b[o - 2] << 8) | b[o - 1]);
        if (boxSize < 16 || boxSize > 4096) return false;
        for (int i = 0; i < 4; i++)
        {
            byte c = b[o + 4 + i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ';
            if (!ok) return false;
        }
        return true;
    }

    private static bool ValidateRtf(byte[] b, int o)
    {
        if (o + 6 > b.Length) return false;
        return b[o + 5] is >= (byte)'0' and <= (byte)'9';
    }

    private static bool ValidateXml(byte[] b, int o)
    {
        if (o + 14 > b.Length) return false;
        int len = Math.Min(80, b.Length - o);
        string sample = System.Text.Encoding.ASCII.GetString(b, o, len);
        return sample.StartsWith("<?xml") && (sample.Contains("version") || sample.Contains("encoding"));
    }

    private static bool ValidatePng(byte[] b, int o)
    {
        // 8-byte magic is strong, but also require an IEND chunk somewhere after.
        var iend = new byte[] { 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };
        int searchLen = Math.Min(b.Length - o - 8, 25 * 1024 * 1024);
        return b.AsSpan(o + 8, searchLen).IndexOf(iend) >= 0;
    }

    private static bool ValidateBzip2(byte[] b, int o)
    {
        // BZh followed by '1'..'9' (block size).
        if (o + 4 > b.Length) return false;
        return b[o + 3] is >= (byte)'1' and <= (byte)'9';
    }

    private static bool ValidateCab(byte[] b, int o)
    {
        if (o + 36 > b.Length) return false;
        uint reserved1 = BitConverter.ToUInt32(b, o + 4);
        if (reserved1 != 0) return false;
        uint total = BitConverter.ToUInt32(b, o + 8);
        if (total < 36 || (long)o + total > b.Length) return false;
        byte verMin = b[o + 24], verMaj = b[o + 25];
        return verMaj <= 3 && verMin <= 10;
    }

    private static bool ValidateLz4(byte[] b, int o)
    {
        // After 4-byte magic, frame descriptor byte FLG: bit 6-7 = version (must be 01).
        if (o + 5 > b.Length) return false;
        byte flg = b[o + 4];
        return (flg & 0xC0) == 0x40;
    }

    private static bool ValidateZstd(byte[] b, int o)
    {
        // Magic 28 B5 2F FD covers ZSTD frames. Frame Header Descriptor byte has reserved bit cleared.
        if (o + 5 > b.Length) return false;
        return (b[o + 4] & 0x08) == 0;
    }

    private static bool ValidateZip(byte[] b, int o)
    {
        // Local file header layout (30 fixed bytes + fname + extra):
        //   4  signature 50 4B 03 04
        //   2  version needed to extract
        //   2  general purpose bit flag
        //   2  compression method
        //   2  last mod time
        //   2  last mod date
        //   4  crc-32
        //   4  compressed size
        //   4  uncompressed size
        //   2  file name length
        //   2  extra field length
        if (o + 30 > b.Length) return false;
        ushort version  = BitConverter.ToUInt16(b, o + 4);
        ushort flags    = BitConverter.ToUInt16(b, o + 6);
        ushort method   = BitConverter.ToUInt16(b, o + 8);
        ushort fnameLen = BitConverter.ToUInt16(b, o + 26);
        ushort extraLen = BitConverter.ToUInt16(b, o + 28);

        if (version > 200) return false;                      // realistically 10..63 for normal zips
        if ((flags & 0xC000) != 0) return false;               // bits 14,15 are unused
        if (!IsKnownZipMethod(method)) return false;
        if (fnameLen > 4096) return false;
        if (o + 30 + fnameLen + extraLen > b.Length) return false;

        // Require a valid EOCD record somewhere after the local header whose CD pointer
        // resolves to a Central Directory entry (signature 50 4B 01 02).
        return FindValidEocd(b, o) >= 0;
    }

    private static bool IsKnownZipMethod(ushort m) =>
        m is 0 or 8 or 9 or 12 or 14 or 93 or 95 or 96 or 97 or 98 or 99;

    /// <summary>Walks all EOCD candidates after the local header at <paramref name="zipStart"/> and returns the file offset of the first one whose central-directory pointer resolves to a 0x504B0102 record. -1 if none.</summary>
    private static int FindValidEocd(byte[] b, int zipStart)
    {
        ReadOnlySpan<byte> eocdMagic = new byte[] { 0x50, 0x4B, 0x05, 0x06 };
        ReadOnlySpan<byte> cdMagic   = new byte[] { 0x50, 0x4B, 0x01, 0x02 };

        var rest = b.AsSpan(zipStart);
        int searchFrom = 30; // can't be earlier than just past local file header
        while (searchFrom + 22 <= rest.Length)
        {
            int idx = rest.Slice(searchFrom).IndexOf(eocdMagic);
            if (idx < 0) return -1;
            int eocdRel = searchFrom + idx;
            searchFrom = eocdRel + 4;

            if (eocdRel + 22 > rest.Length) continue;
            uint cdOffset = BitConverter.ToUInt32(b, zipStart + eocdRel + 16);
            if (cdOffset == 0xFFFFFFFFu) continue; // zip64 — bail out, treat as non-match for now
            if (cdOffset >= (uint)eocdRel) continue;
            int cdAbs = zipStart + (int)cdOffset;
            if (cdAbs < 0 || cdAbs + 4 > b.Length) continue;
            if (!b.AsSpan(cdAbs, 4).SequenceEqual(cdMagic)) continue;

            ushort commentLen = BitConverter.ToUInt16(b, zipStart + eocdRel + 20);
            if (zipStart + eocdRel + 22 + commentLen > b.Length) continue;
            return zipStart + eocdRel;
        }
        return -1;
    }

    // ===== Size detection per format. Returns null if size is not knowable from the bytes alone. =====
    private static long? DetectSize(byte[] bytes, string sigType, int offset)
    {
        try
        {
            return sigType switch
            {
                "CAB" => SizeCab(bytes, offset),
                "ZIP" => SizeZip(bytes, offset),
                "7-Zip" => Size7z(bytes, offset),
                "PE / DOS" => SizePe(bytes, offset),
                "RIFF" => SizeRiff(bytes, offset),
                "PNG" => SizePng(bytes, offset),
                "JPEG" => SizeJpeg(bytes, offset),
                "PDF" => SizePdf(bytes, offset),
                "BMP" => SizeBmp(bytes, offset),
                "ICO" => SizeIco(bytes, offset, type: 1),
                "CUR" => SizeIco(bytes, offset, type: 2),
                "SQLite" => SizeSqlite(bytes, offset),
                _ => null,
            };
        }
        catch
        {
            return null;
        }
    }

    private static long? SizeCab(byte[] b, int off)
    {
        if (off + 12 > b.Length) return null;
        uint total = BitConverter.ToUInt32(b, off + 8);
        if (total < 36 || off + total > b.Length) return null;
        return total;
    }

    private static long? SizeZip(byte[] b, int off)
    {
        int eocdAbs = FindValidEocd(b, off);
        if (eocdAbs < 0) return null;
        ushort commentLen = BitConverter.ToUInt16(b, eocdAbs + 20);
        long end = (long)eocdAbs + 22 + commentLen;
        if (end > b.Length) return null;
        return end - off;
    }

    private static long? Size7z(byte[] b, int off)
    {
        // Start header: 6 sig + 2 ver + 4 crc + 8 nextHdrOff + 8 nextHdrSize + 4 nextHdrCrc = 32 bytes
        if (off + 32 > b.Length) return null;
        long nextHdrOff = BitConverter.ToInt64(b, off + 12);
        long nextHdrSize = BitConverter.ToInt64(b, off + 20);
        if (nextHdrOff < 0 || nextHdrSize < 0) return null;
        long total = 32 + nextHdrOff + nextHdrSize;
        if (off + total > b.Length) return null;
        return total;
    }

    private static long? SizePe(byte[] b, int off)
    {
        try
        {
            using var ms = new MemoryStream(b, off, b.Length - off, writable: false);
            using var pe = new PEReader(ms);
            long end = 0;
            foreach (var s in pe.PEHeaders.SectionHeaders)
                end = Math.Max(end, (long)s.PointerToRawData + s.SizeOfRawData);
            // Include the certificate table (which is a file offset, not RVA).
            var cert = pe.PEHeaders.PEHeader?.CertificateTableDirectory;
            if (cert is not null && cert.Value.Size != 0)
                end = Math.Max(end, (long)cert.Value.RelativeVirtualAddress + cert.Value.Size);
            if (end <= 0 || off + end > b.Length) return null;
            return end;
        }
        catch
        {
            return null;
        }
    }

    private static long? SizeRiff(byte[] b, int off)
    {
        if (off + 8 > b.Length) return null;
        uint sz = BitConverter.ToUInt32(b, off + 4);
        long total = (long)sz + 8;
        if (sz == 0xFFFFFFFF || off + total > b.Length) return null;
        return total;
    }

    private static long? SizePng(byte[] b, int off)
    {
        var iend = new byte[] { 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };
        int idx = ((ReadOnlySpan<byte>)b).Slice(off).IndexOf(iend);
        if (idx < 0) return null;
        long end = (long)off + idx + iend.Length;
        return end - off;
    }

    private static long? SizeJpeg(byte[] b, int off)
    {
        // Walk JPEG markers from off+2. Each marker is FF xx, with most followed by 2-byte big-endian length.
        int i = off + 2;
        while (i + 1 < b.Length)
        {
            if (b[i] != 0xFF) return null;
            byte m = b[i + 1];
            i += 2;
            // 0xFF stuffing (multiple FFs allowed).
            if (m == 0xFF) { i--; continue; }
            if (m == 0xD9) return i - off; // EOI
            if (m == 0xD8) continue;        // SOI (shouldn't repeat but skip)
            if (m >= 0xD0 && m <= 0xD7) continue; // RSTn — no payload
            // Standalone markers with payload length next 2 bytes (big-endian).
            if (i + 2 > b.Length) return null;
            int len = (b[i] << 8) | b[i + 1];
            i += len;
            if (len < 2) return null;
            // SOS marker: payload followed by entropy-coded data; need to scan for next non-stuffed FF marker.
            if (m == 0xDA)
            {
                while (i < b.Length - 1)
                {
                    if (b[i] == 0xFF && b[i + 1] != 0x00 && !(b[i + 1] >= 0xD0 && b[i + 1] <= 0xD7))
                        break;
                    i++;
                }
            }
        }
        return null;
    }

    private static long? SizePdf(byte[] b, int off)
    {
        var eof = new byte[] { 0x25, 0x25, 0x45, 0x4F, 0x46 }; // %%EOF
        // Find the LAST %%EOF after off (PDFs can have incremental updates).
        var span = ((ReadOnlySpan<byte>)b).Slice(off);
        int lastFound = -1;
        int searchFrom = 0;
        while (true)
        {
            int idx = span.Slice(searchFrom).IndexOf(eof);
            if (idx < 0) break;
            lastFound = searchFrom + idx;
            searchFrom = lastFound + eof.Length;
        }
        if (lastFound < 0) return null;
        int end = lastFound + eof.Length;
        // Include trailing newline if any.
        while (end < span.Length && (span[end] == 0x0A || span[end] == 0x0D)) end++;
        return end;
    }

    private static long? SizeBmp(byte[] b, int off)
    {
        if (off + 6 > b.Length) return null;
        uint total = BitConverter.ToUInt32(b, off + 2);
        if (total < 54 || off + total > b.Length) return null;
        return total;
    }

    private static long? SizeIco(byte[] b, int off, int type)
    {
        if (off + 6 > b.Length) return null;
        ushort kind = BitConverter.ToUInt16(b, off + 2);
        if (kind != type) return null;
        ushort count = BitConverter.ToUInt16(b, off + 4);
        if (count == 0 || count > 256) return null;
        // Directory entry = 16 bytes; entries follow header.
        int dirStart = off + 6;
        if (dirStart + count * 16 > b.Length) return null;
        long maxEnd = dirStart + count * 16;
        for (int i = 0; i < count; i++)
        {
            int e = dirStart + i * 16;
            uint entrySize = BitConverter.ToUInt32(b, e + 8);
            uint entryOffset = BitConverter.ToUInt32(b, e + 12);
            long end = (long)entryOffset + entrySize;
            if (end > maxEnd) maxEnd = end;
        }
        // entry offsets are relative to the start of the ICO blob.
        if (off + maxEnd > b.Length) return null;
        return maxEnd;
    }

    private static long? SizeSqlite(byte[] b, int off)
    {
        // Page size at offset 16 (2 bytes big-endian), in_header page count at offset 28 (4 bytes big-endian).
        if (off + 100 > b.Length) return null;
        int pageSize = (b[off + 16] << 8) | b[off + 17];
        if (pageSize == 1) pageSize = 65536;
        uint pageCount = ((uint)b[off + 28] << 24) | ((uint)b[off + 29] << 16) | ((uint)b[off + 30] << 8) | b[off + 31];
        long total = (long)pageSize * pageCount;
        if (total <= 0 || off + total > b.Length) return null;
        return total;
    }

    // ===== Section map helpers =====
    private sealed record SectionSpan(string Name, int FileOffset, int Size);

    private static List<SectionSpan> ReadSectionMap(byte[] bytes)
    {
        var list = new List<SectionSpan>();
        try
        {
            using var ms = new MemoryStream(bytes, writable: false);
            using var pe = new PEReader(ms);
            foreach (var s in pe.PEHeaders.SectionHeaders)
                list.Add(new SectionSpan(s.Name, s.PointerToRawData, s.SizeOfRawData));
        }
        catch { }
        return list;
    }

    private static string LookupSection(List<SectionSpan> sections, int offset, int endOfLastSection)
    {
        foreach (var s in sections)
        {
            if (offset >= s.FileOffset && offset < s.FileOffset + s.Size)
                return s.Name;
        }
        if (offset >= endOfLastSection) return "overlay";
        return "header";
    }
}
