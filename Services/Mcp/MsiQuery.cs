using System.Runtime.InteropServices;
using System.Text;

namespace BinaryExplorer.Services.Mcp;

/// <summary>
/// Read-only Windows Installer (MSI) database reader.
///
/// Uses the native msi.dll database API via P/Invoke rather than the
/// WindowsInstaller.Installer COM automation object — the COM object cannot be
/// activated from a packaged app, which silently broke MSI inspection. The
/// native exports are plain functions and work in packaged and unpackaged
/// processes alike.
/// </summary>
internal static class MsiQuery
{
    /// <summary>Cheap header check: Microsoft Compound File Binary magic.</summary>
    public static bool IsCompoundFileBinary(byte[] bytes) =>
        bytes.Length >= 8
        && bytes[0] == 0xD0 && bytes[1] == 0xCF && bytes[2] == 0x11 && bytes[3] == 0xE0
        && bytes[4] == 0xA1 && bytes[5] == 0xB1 && bytes[6] == 0x1A && bytes[7] == 0xE1;

    // ===================== native msi.dll =====================
    // MSIHANDLE is a 32-bit handle on all architectures.

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiOpenDatabaseW(string szDatabasePath, IntPtr szPersist, out uint phDatabase);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiDatabaseOpenViewW(uint hDatabase, string szQuery, out uint phView);

    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewExecute(uint hView, uint hRecord);

    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewFetch(uint hView, out uint phRecord);

    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewGetColumnInfo(uint hView, uint eColumnInfo, out uint phRecord);

    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiRecordGetFieldCount(uint hRecord);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiRecordGetStringW(uint hRecord, uint iField, StringBuilder szValueBuf, ref uint pcchValueBuf);

    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiCloseHandle(uint hAny);

    private const uint ERROR_SUCCESS = 0;
    private const uint ERROR_MORE_DATA = 234;
    private const uint MSICOLINFO_NAMES = 0;
    // MSIDBOPEN_READONLY is (LPCWSTR)0, i.e. a null persist pointer.

    // ===================== public API =====================

    /// <summary>Open the MSI and pull the whole Property table as a dictionary. Null on error.</summary>
    public static Dictionary<string, string?>? ReadProperties(string msiPath)
    {
        if (MsiOpenDatabaseW(msiPath, IntPtr.Zero, out uint hDb) != ERROR_SUCCESS)
            return null;
        try { return ReadPropertyTable(hDb); }
        finally { MsiCloseHandle(hDb); }
    }

    /// <summary>Count rows in a table. Null if the table doesn't exist or can't be opened.</summary>
    public static int? CountRows(string msiPath, string tableName)
    {
        if (MsiOpenDatabaseW(msiPath, IntPtr.Zero, out uint hDb) != ERROR_SUCCESS)
            return null;
        try
        {
            if (MsiDatabaseOpenViewW(hDb, $"SELECT * FROM `{tableName}`", out uint hView) != ERROR_SUCCESS)
                return null;
            try
            {
                if (MsiViewExecute(hView, 0) != ERROR_SUCCESS) return null;
                int n = 0;
                while (MsiViewFetch(hView, out uint hRec) == ERROR_SUCCESS)
                {
                    MsiCloseHandle(hRec);
                    n++;
                }
                return n;
            }
            finally { MsiCloseHandle(hView); }
        }
        finally { MsiCloseHandle(hDb); }
    }

    /// <summary>Run "SELECT * FROM `tableName`" and return its rows.</summary>
    public static object Query(string msiPath, string tableName)
    {
        if (MsiOpenDatabaseW(msiPath, IntPtr.Zero, out uint hDb) != ERROR_SUCCESS)
            return new { error = $"Couldn't open MSI database: {msiPath}" };
        try
        {
            return RunSelect(hDb, $"SELECT * FROM `{tableName}`")
                ?? new { error = $"Table '{tableName}' not found or not readable." };
        }
        finally { MsiCloseHandle(hDb); }
    }

    /// <summary>Run several queries and return a structured summary.</summary>
    public static object Summarize(string msiPath)
    {
        if (MsiOpenDatabaseW(msiPath, IntPtr.Zero, out uint hDb) != ERROR_SUCCESS)
            return new { error = $"Couldn't open MSI database: {msiPath}" };
        try
        {
            var all = ReadPropertyTable(hDb) ?? new Dictionary<string, string?>();
            var keys = new[]
            {
                "ProductName", "ProductCode", "ProductVersion", "ProductLanguage",
                "Manufacturer", "UpgradeCode",
                "ARPCONTACT", "ARPURLINFOABOUT", "ARPHELPLINK",
                "ALLUSERS", "MSIINSTALLPERUSER",
            };
            var productInfo = new Dictionary<string, string?>();
            foreach (var k in keys) productInfo[k] = all.TryGetValue(k, out var v) ? v : null;

            var files            = RunSelect(hDb, "SELECT * FROM `File`");
            var registry         = RunSelect(hDb, "SELECT * FROM `Registry`");
            var shortcuts        = RunSelect(hDb, "SELECT * FROM `Shortcut`");
            var features         = RunSelect(hDb, "SELECT * FROM `Feature`");
            var customActions    = RunSelect(hDb, "SELECT * FROM `CustomAction`");
            var launchConditions = RunSelect(hDb, "SELECT * FROM `LaunchCondition`");
            var components       = RunSelect(hDb, "SELECT * FROM `Component`");
            var directory        = RunSelect(hDb, "SELECT * FROM `Directory`");
            var tables           = RunSelect(hDb, "SELECT `Name` FROM `_Tables`");

            return new
            {
                path = msiPath,
                productInfo,
                tablesAvailable = (tables as dynamic)?.rows,
                fileCount = (files as dynamic)?.rowCount,
                registryCount = (registry as dynamic)?.rowCount,
                shortcutCount = (shortcuts as dynamic)?.rowCount,
                featureCount = (features as dynamic)?.rowCount,
                customActionCount = (customActions as dynamic)?.rowCount,
                componentCount = (components as dynamic)?.rowCount,
                files,
                registry,
                shortcuts,
                features,
                customActions,
                launchConditions,
                components,
                directory,
            };
        }
        finally { MsiCloseHandle(hDb); }
    }

    // ===================== internals =====================

    private static Dictionary<string, string?>? ReadPropertyTable(uint hDb)
    {
        if (MsiDatabaseOpenViewW(hDb, "SELECT `Property`, `Value` FROM `Property`", out uint hView) != ERROR_SUCCESS)
            return null;
        try
        {
            if (MsiViewExecute(hView, 0) != ERROR_SUCCESS) return null;
            var dict = new Dictionary<string, string?>();
            while (MsiViewFetch(hView, out uint hRec) == ERROR_SUCCESS)
            {
                try
                {
                    string key = RecordString(hRec, 1);
                    if (!string.IsNullOrEmpty(key)) dict[key] = RecordString(hRec, 2);
                }
                finally { MsiCloseHandle(hRec); }
            }
            return dict;
        }
        finally { MsiCloseHandle(hView); }
    }

    /// <summary>Run a SELECT and return { query, columns, rowCount, truncated, rows }, or null on failure.</summary>
    private static object? RunSelect(uint hDb, string sql)
    {
        if (MsiDatabaseOpenViewW(hDb, sql, out uint hView) != ERROR_SUCCESS) return null;
        try
        {
            if (MsiViewExecute(hView, 0) != ERROR_SUCCESS) return null;

            var columns = new List<string>();
            if (MsiViewGetColumnInfo(hView, MSICOLINFO_NAMES, out uint hCols) == ERROR_SUCCESS)
            {
                try
                {
                    uint cc = MsiRecordGetFieldCount(hCols);
                    for (uint f = 1; f <= cc; f++) columns.Add(RecordString(hCols, f));
                }
                finally { MsiCloseHandle(hCols); }
            }

            const int RowCap = 5000;
            var rows = new List<Dictionary<string, string>>();
            while (rows.Count < RowCap && MsiViewFetch(hView, out uint hRec) == ERROR_SUCCESS)
            {
                try
                {
                    uint fc = MsiRecordGetFieldCount(hRec);
                    var row = new Dictionary<string, string>((int)fc);
                    for (uint f = 1; f <= fc; f++)
                    {
                        string col = f - 1 < columns.Count ? columns[(int)f - 1] : $"col{f}";
                        row[col] = RecordString(hRec, f);
                    }
                    rows.Add(row);
                }
                finally { MsiCloseHandle(hRec); }
            }

            return new
            {
                query = sql,
                columns = columns.ToArray(),
                rowCount = rows.Count,
                truncated = rows.Count >= RowCap,
                rows,
            };
        }
        finally { MsiCloseHandle(hView); }
    }

    /// <summary>Read one string field of a record, sizing the buffer in two calls.</summary>
    private static string RecordString(uint hRecord, uint field)
    {
        uint cch = 0;
        uint r = MsiRecordGetStringW(hRecord, field, new StringBuilder(), ref cch);
        if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) return "";
        if (cch == 0) return "";
        cch++; // room for the null terminator
        var sb = new StringBuilder((int)cch);
        r = MsiRecordGetStringW(hRecord, field, sb, ref cch);
        return r == ERROR_SUCCESS ? sb.ToString() : "";
    }
}
