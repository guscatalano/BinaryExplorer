using System.Reflection;

namespace BinaryExplorer.Services.Mcp;

/// <summary>
/// Lightweight Windows Installer (MSI) reader using the
/// WindowsInstaller.Installer COM type. No third-party deps.
/// Read-only.
/// </summary>
internal static class MsiQuery
{
    /// <summary>Run "SELECT * FROM `tableName`" and return rows.</summary>
    public static object Query(string msiPath, string tableName)
    {
        var installerType = Type.GetTypeFromProgID("WindowsInstaller.Installer");
        if (installerType is null)
            return new { error = "WindowsInstaller.Installer COM type not registered. (Available on every Windows install.)" };

        object? installer = null;
        object? db = null;
        try
        {
            installer = Activator.CreateInstance(installerType)!;
            db = Invoke(installer, "OpenDatabase", msiPath, 0); // 0 = msiOpenDatabaseModeReadOnly
            if (db is null) return new { error = "OpenDatabase returned null." };
            return RunSelect(db, $"SELECT * FROM `{tableName}`");
        }
        catch (TargetInvocationException tie) when (tie.InnerException is not null)
        {
            return new { error = "MSI error: " + tie.InnerException.Message };
        }
        catch (Exception ex)
        {
            return new { error = ex.GetType().Name + ": " + ex.Message };
        }
        finally
        {
            ReleaseCom(db);
            ReleaseCom(installer);
        }
    }

    /// <summary>Run several interesting queries and return a structured summary.</summary>
    public static object Summarize(string msiPath)
    {
        var installerType = Type.GetTypeFromProgID("WindowsInstaller.Installer");
        if (installerType is null)
            return new { error = "WindowsInstaller.Installer COM type not registered." };

        object? installer = null;
        object? db = null;
        try
        {
            installer = Activator.CreateInstance(installerType)!;
            db = Invoke(installer, "OpenDatabase", msiPath, 0);
            if (db is null) return new { error = "OpenDatabase returned null." };

            var properties = TryProperties(db);
            var files = TryRun(db, "SELECT * FROM `File`");
            var registry = TryRun(db, "SELECT * FROM `Registry`");
            var shortcuts = TryRun(db, "SELECT * FROM `Shortcut`");
            var features = TryRun(db, "SELECT * FROM `Feature`");
            var customActions = TryRun(db, "SELECT * FROM `CustomAction`");
            var launchConditions = TryRun(db, "SELECT * FROM `LaunchCondition`");
            var components = TryRun(db, "SELECT * FROM `Component`");
            var directory = TryRun(db, "SELECT * FROM `Directory`");
            var tables = TryRun(db, "SELECT `Name` FROM `_Tables`");

            return new
            {
                path = msiPath,
                productInfo = properties,
                tablesAvailable = (tables as dynamic)?.rows,
                fileCount = (files as dynamic)?.rowCount,
                registryCount = (registry as dynamic)?.rowCount,
                shortcutCount = (shortcuts as dynamic)?.rowCount,
                featureCount = (features as dynamic)?.rowCount,
                customActionCount = (customActions as dynamic)?.rowCount,
                componentCount = (components as dynamic)?.rowCount,
                files = files,
                registry = registry,
                shortcuts = shortcuts,
                features = features,
                customActions = customActions,
                launchConditions = launchConditions,
                components = components,
                directory = directory,
            };
        }
        catch (TargetInvocationException tie) when (tie.InnerException is not null)
        {
            return new { error = "MSI error: " + tie.InnerException.Message };
        }
        catch (Exception ex)
        {
            return new { error = ex.GetType().Name + ": " + ex.Message };
        }
        finally
        {
            ReleaseCom(db);
            ReleaseCom(installer);
        }
    }

    private static object? TryRun(object db, string sql)
    {
        try { return RunSelect(db, sql); }
        catch { return null; }
    }

    private static Dictionary<string, string?> TryProperties(object db)
    {
        var props = new Dictionary<string, string?>();
        var keys = new[]
        {
            "ProductName", "ProductCode", "ProductVersion", "ProductLanguage",
            "Manufacturer", "UpgradeCode",
            "ARPCONTACT", "ARPURLINFOABOUT", "ARPHELPLINK",
            "ALLUSERS", "MSIINSTALLPERUSER",
        };
        try
        {
            object? view = Invoke(db, "OpenView", "SELECT `Value` FROM `Property` WHERE `Property` = ?");
            if (view is null) return props;
            try
            {
                foreach (var key in keys)
                {
                    try
                    {
                        var rec = MakeRecord(1);
                        Invoke(rec, "set_StringData", 1, key);
                        Invoke(view, "Execute", rec);
                        var row = Invoke(view, "Fetch");
                        if (row is null) { props[key] = null; ReleaseCom(rec); continue; }
                        string val = Invoke(row, "get_StringData", 1)?.ToString() ?? "";
                        props[key] = val;
                        ReleaseCom(row);
                        ReleaseCom(rec);
                    }
                    catch { props[key] = null; }
                }
            }
            finally
            {
                try { Invoke(view, "Close"); } catch { }
                ReleaseCom(view);
            }
        }
        catch { }
        return props;
    }

    private static object RunSelect(object db, string sql)
    {
        var view = Invoke(db, "OpenView", sql)
            ?? throw new InvalidOperationException("OpenView returned null.");
        try
        {
            Invoke(view, "Execute", null!);

            // Column names: OpenView -> ColumnInfo(0=Names, 1=Types)
            object? colInfo = Invoke(view, "get_ColumnInfo", 0);
            int colCount = 0;
            var columns = new List<string>();
            if (colInfo is not null)
            {
                try
                {
                    colCount = (int)(Invoke(colInfo, "get_FieldCount") ?? 0);
                    for (int i = 1; i <= colCount; i++)
                        columns.Add(Invoke(colInfo, "get_StringData", i)?.ToString() ?? "");
                }
                finally { ReleaseCom(colInfo); }
            }

            var rows = new List<Dictionary<string, string>>();
            const int RowCap = 5000;
            while (rows.Count < RowCap)
            {
                object? record = Invoke(view, "Fetch");
                if (record is null) break;
                try
                {
                    var row = new Dictionary<string, string>(columns.Count);
                    for (int i = 1; i <= colCount; i++)
                    {
                        string val = Invoke(record, "get_StringData", i)?.ToString() ?? "";
                        row[columns[i - 1]] = val;
                    }
                    rows.Add(row);
                }
                finally { ReleaseCom(record); }
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
        finally
        {
            try { Invoke(view, "Close"); } catch { }
            ReleaseCom(view);
        }
    }

    private static object? MakeRecord(int fields)
    {
        var installerType = Type.GetTypeFromProgID("WindowsInstaller.Installer")!;
        var installer = Activator.CreateInstance(installerType)!;
        try
        {
            return Invoke(installer, "CreateRecord", fields);
        }
        finally
        {
            ReleaseCom(installer);
        }
    }

    private static object? Invoke(object target, string member, params object?[] args)
    {
        var t = target.GetType();
        // For property accessors via 'get_'/'set_', the COM dispatch will figure it out from
        // method name in late-bound mode.
        return t.InvokeMember(member,
            BindingFlags.InvokeMethod | BindingFlags.GetProperty | BindingFlags.SetProperty,
            null, target, args);
    }

    private static void ReleaseCom(object? obj)
    {
        if (obj is null) return;
        try
        {
            if (System.Runtime.InteropServices.Marshal.IsComObject(obj))
                System.Runtime.InteropServices.Marshal.ReleaseComObject(obj);
        }
        catch { }
    }
}
