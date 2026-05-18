using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BinaryExplorer.Mcp;

internal static class Tools
{
    public static object[] Describe() => new object[]
    {
        new
        {
            name = "pe_info",
            description = "PE header overview: machine, subsystem, image base, entry point, sections.",
            inputSchema = StringPathSchema("Filesystem path to a Windows PE binary (.exe/.dll/.sys)."),
        },
        new
        {
            name = "hashes",
            description = "Compute MD5, SHA-1, SHA-256, SHA-512, and imphash (FireEye algorithm).",
            inputSchema = StringPathSchema("Filesystem path to a Windows PE binary."),
        },
        new
        {
            name = "imports",
            description = "List statically imported DLLs and the named functions imported from each.",
            inputSchema = StringPathSchema("Filesystem path to a Windows PE binary."),
        },
        new
        {
            name = "exports",
            description = "List the named exports of a PE binary (RVA + name).",
            inputSchema = StringPathSchema("Filesystem path to a Windows PE binary."),
        },
        new
        {
            name = "strings",
            description = "Extract printable ASCII and UTF-16LE strings (min length 6).",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    path = new { type = "string", description = "Filesystem path to a binary." },
                    max = new { type = "integer", description = "Maximum strings to return (default 500).", minimum = 1, maximum = 10000 },
                },
                required = new[] { "path" },
            },
        },
        new
        {
            name = "signature",
            description = "Extract the Authenticode signing certificate subject/issuer/thumbprint/validity.",
            inputSchema = StringPathSchema("Filesystem path to a Windows PE binary."),
        },
    };

    public static async Task<JsonRpcResponse> CallAsync(object? id, string name, JsonElement args)
    {
        try
        {
            string path = args.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(path))
                return ErrorContent(id, "Missing 'path' argument.");
            if (!System.IO.File.Exists(path))
                return ErrorContent(id, $"File not found: {path}");

            byte[] bytes = await System.IO.File.ReadAllBytesAsync(path);

            object payload = name switch
            {
                "pe_info"   => PeInfo(bytes),
                "hashes"    => Hashes(bytes),
                "imports"   => Imports(bytes),
                "exports"   => Exports(bytes),
                "strings"   => StringsTool(bytes, args),
                "signature" => Signature(path),
                _ => null!,
            };
            if (payload is null) return ErrorContent(id, $"Unknown tool: {name}");

            string textJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
            return new JsonRpcResponse(id, new
            {
                content = new object[]
                {
                    new { type = "text", text = textJson },
                },
            }, null);
        }
        catch (Exception ex)
        {
            return ErrorContent(id, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static JsonRpcResponse ErrorContent(object? id, string text) =>
        new(id, new
        {
            content = new object[] { new { type = "text", text } },
            isError = true,
        }, null);

    // ---- Tool implementations ----

    private static object PeInfo(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes, writable: false);
        using var pe = new PEReader(ms);
        var coff = pe.PEHeaders.CoffHeader;
        var opt = pe.PEHeaders.PEHeader;
        var sections = pe.PEHeaders.SectionHeaders
            .Select(s => new
            {
                name = s.Name,
                virtualAddress = s.VirtualAddress,
                virtualSize = s.VirtualSize,
                sizeOfRawData = s.SizeOfRawData,
                pointerToRawData = s.PointerToRawData,
                characteristics = s.SectionCharacteristics.ToString(),
            })
            .ToArray();

        return new
        {
            machine = coff.Machine.ToString(),
            subsystem = opt?.Subsystem.ToString(),
            magic = opt?.Magic.ToString(),
            imageBase = "0x" + (opt?.ImageBase ?? 0).ToString("X"),
            entryPointRva = "0x" + (opt?.AddressOfEntryPoint ?? 0).ToString("X"),
            sizeOfImage = opt?.SizeOfImage,
            hasManagedMetadata = pe.HasMetadata,
            compileTimestampUtc = DateTimeOffset.FromUnixTimeSeconds(coff.TimeDateStamp).UtcDateTime.ToString("u"),
            linker = opt is null ? null : $"{opt.MajorLinkerVersion}.{opt.MinorLinkerVersion}",
            sections,
        };
    }

    private static object Hashes(byte[] bytes)
    {
        string Hex(byte[] h) => Convert.ToHexString(h).ToLowerInvariant();
        var sha256 = SHA256.HashData(bytes);
        return new
        {
            md5     = Hex(MD5.HashData(bytes)),
            sha1    = Hex(SHA1.HashData(bytes)),
            sha256  = Hex(sha256),
            sha512  = Hex(SHA512.HashData(bytes)),
            imphash = TryImphash(bytes),
            sizeBytes = bytes.LongLength,
        };
    }

    private static string? TryImphash(byte[] bytes)
    {
        try
        {
            using var ms = new MemoryStream(bytes, writable: false);
            using var pe = new PEReader(ms);
            var dlls = PeImportsRaw.Read(pe, bytes, out _);
            if (dlls.Count == 0) return null;
            var parts = new List<string>();
            foreach (var dll in dlls)
            {
                string norm = dll.Dll.ToLowerInvariant();
                foreach (var ext in new[] { ".dll", ".ocx", ".sys" })
                    if (norm.EndsWith(ext)) { norm = norm[..^ext.Length]; break; }
                foreach (var fn in dll.Functions) parts.Add($"{norm}.{fn.ToLowerInvariant()}");
                foreach (var o in dll.Ordinals) parts.Add($"{norm}.ord{o}");
            }
            if (parts.Count == 0) return null;
            return Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(string.Join(",", parts)))).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static object Imports(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes, writable: false);
        using var pe = new PEReader(ms);
        var dlls = PeImportsRaw.Read(pe, bytes, out _);
        return new
        {
            dllCount = dlls.Count,
            imports = dlls.Select(d => new { dll = d.Dll, functions = d.Functions, ordinals = d.Ordinals }).ToArray(),
        };
    }

    private static object Exports(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes, writable: false);
        using var pe = new PEReader(ms);
        var dir = pe.PEHeaders.PEHeader?.ExportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return new { count = 0, exports = Array.Empty<object>() };

        if (!PeImportsRaw.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int exportOff))
            return new { count = 0, exports = Array.Empty<object>() };

        uint numberOfNames = BitConverter.ToUInt32(bytes, exportOff + 24);
        uint addressOfFunctions = BitConverter.ToUInt32(bytes, exportOff + 28);
        uint addressOfNames = BitConverter.ToUInt32(bytes, exportOff + 32);
        uint addressOfNameOrdinals = BitConverter.ToUInt32(bytes, exportOff + 36);

        var results = new List<object>();
        if (PeImportsRaw.TryRvaToOffset(pe, (int)addressOfNames, out int nameTableOff)
            && PeImportsRaw.TryRvaToOffset(pe, (int)addressOfNameOrdinals, out int ordTableOff)
            && PeImportsRaw.TryRvaToOffset(pe, (int)addressOfFunctions, out int fnTableOff))
        {
            for (int i = 0; i < numberOfNames && i < 8192; i++)
            {
                int nameRvaOff = nameTableOff + i * 4;
                if (nameRvaOff + 4 > bytes.Length) break;
                uint nameRva = BitConverter.ToUInt32(bytes, nameRvaOff);
                if (!PeImportsRaw.TryRvaToOffset(pe, (int)nameRva, out int nOff)) continue;
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
                results.Add(new { name = fnName, rva = "0x" + fnRva.ToString("X") });
            }
        }
        return new { count = results.Count, exports = results };
    }

    private static object StringsTool(byte[] bytes, JsonElement args)
    {
        int max = args.TryGetProperty("max", out var mEl) && mEl.TryGetInt32(out int m) ? Math.Clamp(m, 1, 10000) : 500;
        var list = new List<string>();

        // ASCII
        int start = -1;
        for (int i = 0; i < bytes.Length && list.Count < max; i++)
        {
            byte b = bytes[i];
            bool printable = b >= 0x20 && b < 0x7F;
            if (printable) { if (start < 0) start = i; }
            else
            {
                if (start >= 0 && i - start >= 6 && i - start <= 512)
                    list.Add(Encoding.ASCII.GetString(bytes, start, i - start));
                start = -1;
            }
        }

        // UTF-16LE
        start = -1;
        for (int i = 0; i + 1 < bytes.Length && list.Count < max; i += 2)
        {
            bool printable = bytes[i + 1] == 0 && bytes[i] >= 0x20 && bytes[i] < 0x7F;
            if (printable) { if (start < 0) start = i; }
            else
            {
                if (start >= 0)
                {
                    int cc = (i - start) / 2;
                    if (cc >= 6 && cc <= 512)
                        list.Add(Encoding.Unicode.GetString(bytes, start, i - start));
                }
                start = -1;
            }
        }

        return new { count = list.Count, truncated = list.Count >= max, strings = list };
    }

    private static object Signature(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            var raw = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
            var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(raw.GetRawCertData());
#pragma warning restore SYSLIB0057
            return new
            {
                signed = true,
                subject = cert.Subject,
                issuer = cert.Issuer,
                thumbprint = cert.Thumbprint,
                serialNumber = cert.SerialNumber,
                notBefore = cert.NotBefore.ToUniversalTime().ToString("u"),
                notAfter  = cert.NotAfter.ToUniversalTime().ToString("u"),
                signatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value,
            };
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return new { signed = false, reason = "No embedded Authenticode certificate." };
        }
    }

    // Helpers
    private static object StringPathSchema(string desc) => new
    {
        type = "object",
        properties = new
        {
            path = new { type = "string", description = desc },
        },
        required = new[] { "path" },
    };
}
