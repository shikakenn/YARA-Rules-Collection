/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule AtomTable_Inject
{
    meta:
        id = "5YQFiMzaVUsNp4se45AuqS"
        fingerprint = "v1_sha256_80afe76a4860ace6117fbbbe44b2ea6ebf625d97f07e1fc5b8d39172e2736c00"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        Description = " Detect AtomBombing technique"

    strings:
        $var1 = "GlobalAddAtom"
        $var2 = "GlobalGetAtomName"
        $var3 = "QueueUserAPC"
    condition:
        all of them
}

rule DLL_inject
{
    meta:
        id = "7CB4MU3F0mLcjAA8T7lSJU"
        fingerprint = "v1_sha256_3e0c86c35df15afcb8c0fd27e935d8f8a791d9067f0a30d781464ff4a3edee62"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        Description = "Check for DLL Injection"

    strings:
        $var1 = "OpenProcess"
        $var2 = "VirtualAllocEx"
        $var3 = "LoadLibraryA"
        $var4 = "CreateFileA"
        $var5 = "WriteProcessMemory"
        $var6 = "HeapAlloc"
        $var7 = "GetProcAddress"
        $var8 = "CreateRemoteThread"
    condition:
        4 of them
}

rule Inject_Thread 
{
    meta:
        id = "5Lf0YnJBpPokXdtAYlvraR"
        fingerprint = "v1_sha256_af5109733f579e7072ab2992d163951bf4badeec4d3e43e12fd6016225b2f2ca"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r modified by @fr0gger_"
        description = "Code injection with CreateRemoteThread in a remote process"
        category = "INFO"

    strings:
        $c1 = "OpenProcess" 
        $c2 = "VirtualAllocEx" 
        $c3 = "NtWriteVirtualMemory" 
        $c4 = "WriteProcessMemory" 
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c1 )
}

rule Win_Hook 
{
    meta:
        id = "6LA6HKDjUEYEvCCB7zdnra"
        fingerprint = "v1_sha256_be2b1d36d41725f419ec95b0d00d61db5c7e8a315122cb82aee01e6a3c555ce7"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Affect hook table"
        category = "INFO"

    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"         
    condition:
        $f1 and 1 of ($c*)
}
