using System.Runtime.InteropServices;
using System.Text;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class VersionInfoInspector : IBinaryInspector
{
    public string Name => "VersionInfo";

    private static readonly string[] StandardKeys = new[]
    {
        "CompanyName", "ProductName", "FileDescription", "FileVersion", "ProductVersion",
        "InternalName", "OriginalFilename", "LegalCopyright", "LegalTrademarks",
        "Comments", "PrivateBuild", "SpecialBuild",
    };

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                int dwHandle;
                uint size = GetFileVersionInfoSizeW(context.Path, out dwHandle);
                if (size == 0)
                {
                    findings.Add(new Finding("Version info", "Not present"));
                    return new InspectionResult { InspectorName = Name, Headline = "No VS_VERSIONINFO resource", Findings = findings };
                }

                var buf = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (!GetFileVersionInfoW(context.Path, 0, size, buf))
                    {
                        findings.Add(new Finding("Version info", "GetFileVersionInfoW failed",
                            $"Win32 error: {Marshal.GetLastWin32Error()}", Severity.Warning));
                        return new InspectionResult { InspectorName = Name, Headline = "Version info read failed", Findings = findings };
                    }

                    // Find the first translation entry.
                    if (!VerQueryValueW(buf, @"\VarFileInfo\Translation", out IntPtr trBuf, out uint trLen) || trLen < 4)
                    {
                        findings.Add(new Finding("Version info", "No \\VarFileInfo\\Translation block"));
                        return new InspectionResult { InspectorName = Name, Headline = "No translation block", Findings = findings };
                    }
                    ushort lang = (ushort)Marshal.ReadInt16(trBuf);
                    ushort cp = (ushort)Marshal.ReadInt16(trBuf + 2);
                    string langCp = $"{lang:X4}{cp:X4}";
                    findings.Add(new Finding("Translation", $"lang=0x{lang:X4} codepage=0x{cp:X4}"));

                    string originalName = "(unset)";
                    foreach (var key in StandardKeys)
                    {
                        string path = $@"\StringFileInfo\{langCp}\{key}";
                        if (VerQueryValueW(buf, path, out IntPtr p, out uint l) && l > 1)
                        {
                            string val = Marshal.PtrToStringUni(p, (int)l - 1) ?? "";
                            findings.Add(new Finding(key, val));
                            if (key == "OriginalFilename") originalName = val;
                        }
                    }

                    // VS_FIXEDFILEINFO via root \\ .
                    if (VerQueryValueW(buf, "\\", out IntPtr ffi, out uint ffiSize) && ffiSize >= 52)
                    {
                        uint fileVerMS = (uint)Marshal.ReadInt32(ffi, 8);
                        uint fileVerLS = (uint)Marshal.ReadInt32(ffi, 12);
                        uint prodVerMS = (uint)Marshal.ReadInt32(ffi, 16);
                        uint prodVerLS = (uint)Marshal.ReadInt32(ffi, 20);
                        findings.Add(new Finding(
                            "FixedFileVersion",
                            $"{(fileVerMS >> 16)}.{(fileVerMS & 0xFFFF)}.{(fileVerLS >> 16)}.{(fileVerLS & 0xFFFF)}"));
                        findings.Add(new Finding(
                            "FixedProductVersion",
                            $"{(prodVerMS >> 16)}.{(prodVerMS & 0xFFFF)}.{(prodVerLS >> 16)}.{(prodVerLS & 0xFFFF)}"));
                    }

                    string headline = originalName == "(unset)"
                        ? "Version info present"
                        : $"OriginalFilename: {originalName}";

                    // Compare disk filename vs OriginalFilename — common renamed-binary tell.
                    string actual = System.IO.Path.GetFileName(context.Path);
                    if (originalName != "(unset)"
                        && !originalName.Equals(actual, StringComparison.OrdinalIgnoreCase)
                        && !originalName.Equals(System.IO.Path.GetFileNameWithoutExtension(actual), StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(new Finding(
                            "Renamed?",
                            $"Disk: {actual}  vs  OriginalFilename: {originalName}",
                            "Mismatch is common with malware that renames known binaries.",
                            Severity.Warning));
                    }

                    return new InspectionResult { InspectorName = Name, Headline = headline, Findings = findings };
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Version info inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileVersionInfoSizeW(string lptstrFilename, out int lpdwHandle);

    [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileVersionInfoW(string lptstrFilename, int dwHandle, uint dwLen, IntPtr lpData);

    [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VerQueryValueW(IntPtr pBlock, string lpSubBlock, out IntPtr lplpBuffer, out uint puLen);
}
