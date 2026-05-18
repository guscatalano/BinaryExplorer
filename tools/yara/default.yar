/*
   BinaryExplorer — default starter rules.
   These are intentionally simple and high-recall so they're useful as a
   first pass. Pair them with curated public rules (e.g. Florian Roth's
   `signature-base`) for serious work.
*/

import "pe"

rule BE_MZ_PE_Header
{
    meta:
        description = "File begins with an MZ DOS header and has a PE signature at e_lfanew."
        author      = "BinaryExplorer"
        category    = "format"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe in (0..0x4000)
}

rule BE_NET_Assembly
{
    meta:
        description = "Managed .NET assembly: PE with COR20 'BSJB' metadata header."
        author      = "BinaryExplorer"
        category    = "format"
    strings:
        $bsjb = "BSJB"
    condition:
        $bsjb and pe.is_pe
}

rule BE_Packed_UPX
{
    meta:
        description = "UPX-packed PE (UPX0/UPX1 section names + UPX! magic)."
        author      = "BinaryExplorer"
        category    = "packer"
    condition:
        pe.is_pe and
        (
            for any s in pe.sections : (s.name == "UPX0" or s.name == "UPX1" or s.name == "UPX2")
        )
}

rule BE_Packed_Common
{
    meta:
        description = "Section names of well-known commercial packers/protectors."
        author      = "BinaryExplorer"
        category    = "packer"
    condition:
        pe.is_pe and
        (
            for any s in pe.sections : (
                s.name == ".aspack"  or s.name == ".adata"  or
                s.name == ".vmp0"    or s.name == ".vmp1"   or s.name == ".vmp2"   or
                s.name == ".themida" or s.name == "Themida" or
                s.name == ".enigma1" or s.name == ".enigma2" or
                s.name == ".petite"  or
                s.name == ".mpress1" or s.name == ".mpress2" or
                s.name == ".nsp0"    or s.name == ".nsp1"   or s.name == ".nsp2"   or
                s.name == "FSG!"
            )
        )
}

rule BE_High_Entropy_Section
{
    meta:
        description = "PE contains at least one section with entropy >= 7.5 (likely encrypted/compressed)."
        author      = "BinaryExplorer"
        category    = "packer"
    condition:
        pe.is_pe and
        for any s in pe.sections : ( math.entropy(s.raw_data_offset, s.raw_data_size) >= 7.5 )
}

rule BE_AntiDebug_Imports
{
    meta:
        description = "Imports classic anti-debug APIs."
        author      = "BinaryExplorer"
        category    = "anti-analysis"
    condition:
        pe.is_pe and
        (
            pe.imports("kernel32.dll", "IsDebuggerPresent") or
            pe.imports("kernel32.dll", "CheckRemoteDebuggerPresent") or
            pe.imports("ntdll.dll",    "NtQueryInformationProcess") or
            pe.imports("kernel32.dll", "OutputDebugStringA") or
            pe.imports("ntdll.dll",    "NtSetInformationThread")
        )
}

rule BE_ProcessInjection_Imports
{
    meta:
        description = "Imports the classic process-injection trio."
        author      = "BinaryExplorer"
        category    = "capabilities"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("kernel32.dll", "CreateRemoteThreadEx") or
            pe.imports("ntdll.dll",    "NtCreateThreadEx") or
            pe.imports("ntdll.dll",    "RtlCreateUserThread")
        )
}

rule BE_Keylog_Imports
{
    meta:
        description = "Imports keyboard / screen-capture APIs commonly used for keylogging."
        author      = "BinaryExplorer"
        category    = "capabilities"
    condition:
        pe.is_pe and
        (
            pe.imports("user32.dll", "SetWindowsHookExA") or
            pe.imports("user32.dll", "SetWindowsHookExW") or
            pe.imports("user32.dll", "GetAsyncKeyState") or
            pe.imports("user32.dll", "GetKeyboardState") or
            pe.imports("gdi32.dll",  "BitBlt")
        )
}

rule BE_Network_Imports
{
    meta:
        description = "Imports networking APIs (WinHTTP / WinInet / Winsock)."
        author      = "BinaryExplorer"
        category    = "capabilities"
    condition:
        pe.is_pe and
        (
            pe.imports("winhttp.dll",  "WinHttpOpen") or
            pe.imports("wininet.dll",  "InternetOpenA") or
            pe.imports("wininet.dll",  "InternetOpenW") or
            pe.imports("urlmon.dll",   "URLDownloadToFileA") or
            pe.imports("urlmon.dll",   "URLDownloadToFileW") or
            pe.imports("ws2_32.dll",   "WSAStartup")
        )
}

rule BE_RPC_Server
{
    meta:
        description = "Looks like an RPC server: registers an interface and listens."
        author      = "BinaryExplorer"
        category    = "interfaces"
    condition:
        pe.is_pe and
        (
            pe.imports("rpcrt4.dll", "RpcServerRegisterIf") or
            pe.imports("rpcrt4.dll", "RpcServerRegisterIf2") or
            pe.imports("rpcrt4.dll", "RpcServerRegisterIfEx") or
            pe.imports("rpcrt4.dll", "NdrServerInitializeNew")
        )
}

rule BE_COM_InProc_Server
{
    meta:
        description = "Exports the canonical in-process COM server entry points."
        author      = "BinaryExplorer"
        category    = "interfaces"
    condition:
        pe.is_pe and
        pe.exports("DllGetClassObject") and
        pe.exports("DllCanUnloadNow") and
        (pe.exports("DllRegisterServer") or pe.exports("DllUnregisterServer"))
}

rule BE_Embedded_CAB
{
    meta:
        description = "Contains an MSCF (Microsoft Cabinet) header anywhere in the file."
        author      = "BinaryExplorer"
        category    = "embedded"
    strings:
        $mscf = "MSCF"
    condition:
        $mscf
}

rule BE_Embedded_ZIP
{
    meta:
        description = "Contains a ZIP local file header (also OOXML / JAR / APK)."
        author      = "BinaryExplorer"
        category    = "embedded"
    strings:
        $pk = { 50 4B 03 04 }
    condition:
        $pk
}

rule BE_Embedded_PE
{
    meta:
        description = "Contains a second PE binary embedded after offset 0x400 (dropper indicator)."
        author      = "BinaryExplorer"
        category    = "embedded"
    strings:
        $mz_inner = { 4D 5A } // any subsequent MZ
    condition:
        pe.is_pe and
        for any i in (1..#mz_inner) : (@mz_inner[i] > 0x400)
}
