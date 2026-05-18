using System.Reflection.PortableExecutable;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class CapabilitiesInspector : IBinaryInspector
{
    public string Name => "Capabilities";

    private static readonly Dictionary<string, (string Category, string Description)> ApiCatalog =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // ---- Process Injection ----
            ["VirtualAllocEx"]          = ("Process Injection", "allocate memory in another process"),
            ["WriteProcessMemory"]      = ("Process Injection", "write bytes into another process"),
            ["CreateRemoteThread"]      = ("Process Injection", "start a thread in another process"),
            ["CreateRemoteThreadEx"]    = ("Process Injection", "start a thread in another process (Ex)"),
            ["NtCreateThreadEx"]        = ("Process Injection", "low-level remote-thread creation"),
            ["RtlCreateUserThread"]     = ("Process Injection", "low-level remote-thread creation"),
            ["NtMapViewOfSection"]      = ("Process Injection", "map shared section into a process"),
            ["QueueUserAPC"]            = ("Process Injection", "queue an APC to a target thread"),
            ["NtQueueApcThread"]        = ("Process Injection", "queue an APC to a target thread (Nt)"),
            ["SetThreadContext"]        = ("Process Injection", "redirect thread execution"),
            ["NtAllocateVirtualMemory"] = ("Process Injection", "low-level VirtualAllocEx"),
            ["NtWriteVirtualMemory"]    = ("Process Injection", "low-level WriteProcessMemory"),
            ["VirtualProtectEx"]        = ("Process Injection", "change page protections in another process"),
            ["OpenProcess"]             = ("Process Injection", "obtain handle to another process"),

            // ---- Anti-Debug / Anti-Analysis ----
            ["IsDebuggerPresent"]           = ("Anti-Debug", "user-mode debugger presence flag"),
            ["CheckRemoteDebuggerPresent"]  = ("Anti-Debug", "check if any process is debugging us"),
            ["NtQueryInformationProcess"]   = ("Anti-Debug", "ProcessDebugPort / ProcessDebugFlags trick"),
            ["OutputDebugStringA"]          = ("Anti-Debug", "OutputDebugString last-error trick"),
            ["OutputDebugStringW"]          = ("Anti-Debug", "OutputDebugString last-error trick"),
            ["DbgUiRemoteBreakin"]          = ("Anti-Debug", "blocked-on-debugger trick"),
            ["NtSetInformationThread"]      = ("Anti-Debug", "ThreadHideFromDebugger"),
            ["FindWindowA"]                 = ("Anti-Debug", "scan for analysis tool window names"),
            ["FindWindowW"]                 = ("Anti-Debug", "scan for analysis tool window names"),

            // ---- Cryptography ----
            ["CryptEncrypt"]            = ("Crypto", "CryptoAPI encrypt"),
            ["CryptDecrypt"]            = ("Crypto", "CryptoAPI decrypt"),
            ["CryptCreateHash"]         = ("Crypto", "CryptoAPI hashing"),
            ["CryptHashData"]           = ("Crypto", "CryptoAPI hashing"),
            ["CryptAcquireContextA"]    = ("Crypto", "CryptoAPI context"),
            ["CryptAcquireContextW"]    = ("Crypto", "CryptoAPI context"),
            ["CryptDeriveKey"]          = ("Crypto", "derive symmetric key"),
            ["CryptGenKey"]             = ("Crypto", "generate symmetric key"),
            ["BCryptEncrypt"]           = ("Crypto", "CNG encrypt"),
            ["BCryptDecrypt"]           = ("Crypto", "CNG decrypt"),
            ["BCryptHashData"]          = ("Crypto", "CNG hashing"),
            ["BCryptGenRandom"]         = ("Crypto", "CNG random"),

            // ---- Network ----
            ["WinHttpOpen"]             = ("Network", "WinHTTP session"),
            ["WinHttpConnect"]          = ("Network", "WinHTTP connect"),
            ["WinHttpSendRequest"]      = ("Network", "WinHTTP HTTP request"),
            ["InternetOpenA"]           = ("Network", "WinInet session"),
            ["InternetOpenW"]           = ("Network", "WinInet session"),
            ["InternetConnectA"]        = ("Network", "WinInet connect"),
            ["InternetConnectW"]        = ("Network", "WinInet connect"),
            ["HttpOpenRequestA"]        = ("Network", "WinInet HTTP request"),
            ["HttpOpenRequestW"]        = ("Network", "WinInet HTTP request"),
            ["URLDownloadToFileA"]      = ("Network", "download file from URL"),
            ["URLDownloadToFileW"]      = ("Network", "download file from URL"),
            ["WSAStartup"]              = ("Network", "Winsock initialization"),
            ["socket"]                  = ("Network", "BSD socket"),
            ["connect"]                 = ("Network", "BSD connect"),
            ["recv"]                    = ("Network", "BSD recv"),
            ["send"]                    = ("Network", "BSD send"),
            ["getaddrinfo"]             = ("Network", "DNS resolution"),
            ["gethostbyname"]           = ("Network", "DNS resolution (legacy)"),
            ["DnsQuery_A"]              = ("Network", "DNS resolution"),
            ["DnsQuery_W"]              = ("Network", "DNS resolution"),

            // ---- Persistence ----
            ["SetWindowsHookExA"]       = ("Persistence", "Windows hook (incl. keylogging)"),
            ["SetWindowsHookExW"]       = ("Persistence", "Windows hook (incl. keylogging)"),
            ["CreateServiceA"]          = ("Persistence", "create Windows service"),
            ["CreateServiceW"]          = ("Persistence", "create Windows service"),
            ["StartServiceCtrlDispatcherA"] = ("Persistence", "register as a service host"),
            ["StartServiceCtrlDispatcherW"] = ("Persistence", "register as a service host"),
            ["CoCreateInstance"]        = ("Persistence", "COM activation (potential COM hijack)"),
            ["CoGetClassObject"]        = ("Persistence", "COM activation (potential COM hijack)"),

            // ---- File ops ----
            ["CreateFileA"]             = ("File", "open/create file"),
            ["CreateFileW"]             = ("File", "open/create file"),
            ["ReadFile"]                = ("File", "read"),
            ["WriteFile"]               = ("File", "write"),
            ["MoveFileA"]               = ("File", "rename / move"),
            ["MoveFileW"]               = ("File", "rename / move"),
            ["MoveFileExA"]             = ("File", "rename / move"),
            ["MoveFileExW"]             = ("File", "rename / move"),
            ["DeleteFileA"]             = ("File", "delete"),
            ["DeleteFileW"]             = ("File", "delete"),
            ["CopyFileA"]               = ("File", "copy"),
            ["CopyFileW"]               = ("File", "copy"),
            ["SetFileAttributesA"]      = ("File", "set attributes (hide etc.)"),
            ["SetFileAttributesW"]      = ("File", "set attributes (hide etc.)"),

            // ---- Registry ----
            ["RegOpenKeyExA"]           = ("Registry", "open key"),
            ["RegOpenKeyExW"]           = ("Registry", "open key"),
            ["RegCreateKeyExA"]         = ("Registry", "create key"),
            ["RegCreateKeyExW"]         = ("Registry", "create key"),
            ["RegSetValueExA"]          = ("Registry", "write value"),
            ["RegSetValueExW"]          = ("Registry", "write value"),
            ["RegDeleteKeyA"]           = ("Registry", "delete key"),
            ["RegDeleteKeyW"]           = ("Registry", "delete key"),
            ["RegDeleteValueA"]         = ("Registry", "delete value"),
            ["RegDeleteValueW"]         = ("Registry", "delete value"),
            ["RegGetValueA"]            = ("Registry", "read value"),
            ["RegGetValueW"]            = ("Registry", "read value"),

            // ---- Token / Privileges ----
            ["AdjustTokenPrivileges"]   = ("Tokens", "enable SeDebugPrivilege etc."),
            ["OpenProcessToken"]        = ("Tokens", "obtain process token"),
            ["LookupPrivilegeValueA"]   = ("Tokens", "resolve privilege LUID"),
            ["LookupPrivilegeValueW"]   = ("Tokens", "resolve privilege LUID"),
            ["ImpersonateLoggedOnUser"] = ("Tokens", "impersonate another user"),
            ["DuplicateTokenEx"]        = ("Tokens", "duplicate token (UAC bypass / lateral)"),

            // ---- Keylog / Screen capture ----
            ["GetAsyncKeyState"]        = ("Keylog/Screen", "poll keyboard state"),
            ["GetKeyboardState"]        = ("Keylog/Screen", "snapshot keyboard state"),
            ["GetDC"]                   = ("Keylog/Screen", "obtain screen DC"),
            ["GetDesktopWindow"]        = ("Keylog/Screen", "desktop window handle"),
            ["BitBlt"]                  = ("Keylog/Screen", "copy pixels (screenshot)"),
            ["PrintWindow"]             = ("Keylog/Screen", "capture a window"),

            // ---- Process discovery ----
            ["CreateToolhelp32Snapshot"] = ("Discovery", "enumerate processes/modules"),
            ["Process32FirstW"]          = ("Discovery", "enumerate processes"),
            ["Process32NextW"]           = ("Discovery", "enumerate processes"),
            ["EnumProcesses"]            = ("Discovery", "enumerate processes (PSAPI)"),

            // ---- Code execution helpers ----
            ["ShellExecuteA"]           = ("Execution", "shell-execute another program"),
            ["ShellExecuteW"]           = ("Execution", "shell-execute another program"),
            ["ShellExecuteExA"]         = ("Execution", "shell-execute another program"),
            ["ShellExecuteExW"]         = ("Execution", "shell-execute another program"),
            ["CreateProcessA"]          = ("Execution", "spawn a process"),
            ["CreateProcessW"]          = ("Execution", "spawn a process"),
            ["WinExec"]                 = ("Execution", "spawn a process (legacy)"),
            ["LoadLibraryA"]            = ("Execution", "load DLL dynamically"),
            ["LoadLibraryW"]            = ("Execution", "load DLL dynamically"),
            ["LoadLibraryExA"]          = ("Execution", "load DLL dynamically (Ex)"),
            ["LoadLibraryExW"]          = ("Execution", "load DLL dynamically (Ex)"),
            ["GetProcAddress"]          = ("Execution", "resolve symbol in loaded module"),
        };

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                using var ms = new MemoryStream(context.Bytes, writable: false);
                using var pe = new PEReader(ms);
                var imports = PeImports.Read(pe, out _);

                var byCategory = new Dictionary<string, List<(string Dll, string Fn, string Desc)>>(StringComparer.Ordinal);

                foreach (var imp in imports)
                {
                    foreach (var fn in imp.Functions)
                    {
                        if (!ApiCatalog.TryGetValue(fn, out var info)) continue;
                        if (!byCategory.TryGetValue(info.Category, out var list))
                            byCategory[info.Category] = list = new();
                        list.Add((imp.Dll, fn, info.Description));
                    }
                }

                if (byCategory.Count == 0)
                {
                    findings.Add(new Finding("Capabilities", "No interesting APIs identified",
                        "Imports table didn't reference any APIs in the known categories. Either the binary is benign, uses uncommon APIs, or imports are resolved dynamically (LoadLibrary/GetProcAddress)."));
                    return new InspectionResult
                    {
                        InspectorName = Name,
                        Headline = "No suspicious capabilities flagged",
                        Findings = findings,
                    };
                }

                foreach (var kv in byCategory.OrderByDescending(k => k.Value.Count))
                {
                    var detail = string.Join("\n",
                        kv.Value
                          .OrderBy(x => x.Fn, StringComparer.OrdinalIgnoreCase)
                          .Select(x => $"  {x.Fn}  ({x.Dll}) — {x.Desc}"));
                    Severity sev = kv.Key switch
                    {
                        "Process Injection" or "Anti-Debug" or "Keylog/Screen" => Severity.Warning,
                        _ => Severity.Info,
                    };
                    findings.Add(new Finding(kv.Key, $"{kv.Value.Count} API(s)", detail, sev));
                }

                string headline = $"{byCategory.Count} categor{(byCategory.Count == 1 ? "y" : "ies")} flagged: " +
                    string.Join(", ", byCategory.Keys.OrderBy(s => s));

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
                    Headline = "Capabilities inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }
}
