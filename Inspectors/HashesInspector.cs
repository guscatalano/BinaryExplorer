using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class HashesInspector : IBinaryInspector
{
    public string Name => "Hashes";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                var bytes = context.Bytes;
                findings.Add(new Finding("MD5", Hex(MD5.HashData(bytes))));
                findings.Add(new Finding("SHA-1", Hex(SHA1.HashData(bytes))));
                findings.Add(new Finding("SHA-256", Hex(SHA256.HashData(bytes))));
                findings.Add(new Finding("SHA-512", Hex(SHA512.HashData(bytes))));

                try
                {
                    var imphash = ComputeImphash(bytes);
                    if (imphash is not null)
                        findings.Add(new Finding("Imphash (FireEye/Mandiant)", imphash,
                            "MD5 of normalized (lowercase, no .dll/.ocx/.sys) DLL.function pairs from imports."));
                    else
                        findings.Add(new Finding("Imphash", "n/a (no imports table)"));
                }
                catch (Exception ex)
                {
                    findings.Add(new Finding("Imphash", "(failed)", ex.Message, Severity.Warning));
                }

                try
                {
                    var auth = ComputeAuthenticodeHash(bytes);
                    if (auth is not null)
                        findings.Add(new Finding("Authenticode SHA-256", Hex(auth),
                            "SHA-256 over PE bytes excluding checksum field and cert table — used by Authenticode signing."));
                }
                catch (Exception ex)
                {
                    findings.Add(new Finding("Authenticode hash", "(failed)", ex.Message, Severity.Warning));
                }

                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = $"SHA-256 {Hex(SHA256.HashData(bytes))[..16]}…",
                    Findings = findings,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Hash computation failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static string? ComputeImphash(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes, writable: false);
        using var pe = new PEReader(ms);
        var imports = PeImports.Read(pe, out _);
        if (imports.Count == 0) return null;

        var parts = new List<string>();
        foreach (var dll in imports)
        {
            if (string.IsNullOrEmpty(dll.Dll)) continue;
            string normDll = dll.Dll.ToLowerInvariant();
            foreach (var ext in new[] { ".dll", ".ocx", ".sys" })
                if (normDll.EndsWith(ext)) { normDll = normDll[..^ext.Length]; break; }

            foreach (var fn in dll.Functions)
                parts.Add($"{normDll}.{fn.ToLowerInvariant()}");
            foreach (var ord in dll.Ordinals)
                parts.Add($"{normDll}.ord{ord}");
        }
        if (parts.Count == 0) return null;
        string joined = string.Join(",", parts);
        return Hex(MD5.HashData(Encoding.ASCII.GetBytes(joined)));
    }

    private static byte[]? ComputeAuthenticodeHash(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes, writable: false);
        using var pe = new PEReader(ms);
        var hdr = pe.PEHeaders;
        if (hdr.PEHeader is null) return null;

        // PE header file offset = e_lfanew (read from DOS header at 0x3C).
        int peHeaderOffset = BitConverter.ToInt32(bytes, 0x3C);
        // Optional header starts at peHeaderOffset + 24.
        int optHdrStart = peHeaderOffset + 24;
        // Checksum lives at optHdr + 64 (same offset for PE32 and PE32+).
        int checksumOffset = optHdrStart + 64;

        bool pe32Plus = hdr.PEHeader.Magic == PEMagic.PE32Plus;
        // Cert table directory entry is at optHdr + 128 (PE32) or +144 (PE32+) — but easier: it's at offset 4*8 within
        // the DataDirectories which start at optHdr + 96 (PE32) or +112 (PE32+). 5th entry (index 4) = security/cert table.
        int dataDirStart = optHdrStart + (pe32Plus ? 112 : 96);
        int certDirEntryOffset = dataDirStart + 4 * 8; // each directory entry is 8 bytes

        uint certTableOffset = BitConverter.ToUInt32(bytes, certDirEntryOffset);
        uint certTableSize = BitConverter.ToUInt32(bytes, certDirEntryOffset + 4);

        using var sha = SHA256.Create();
        // 1) bytes [0, checksumOffset)
        sha.TransformBlock(bytes, 0, checksumOffset, null, 0);
        // 2) skip 4-byte checksum
        int after = checksumOffset + 4;
        // 3) [after, certDirEntryOffset)
        sha.TransformBlock(bytes, after, certDirEntryOffset - after, null, 0);
        // 4) skip 8-byte cert directory entry
        int afterDir = certDirEntryOffset + 8;
        // 5) up to start of cert table (or EOF if no cert table)
        int endOfImage = certTableSize == 0 ? bytes.Length : (int)certTableOffset;
        if (endOfImage < afterDir || endOfImage > bytes.Length) return null;
        sha.TransformFinalBlock(bytes, afterDir, endOfImage - afterDir);
        return sha.Hash;
    }
}
