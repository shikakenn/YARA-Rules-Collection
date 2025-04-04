/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule AtomTable_Inject
{
    meta:
        id = "eeSFy8F5aDe0O4kozw9Hs"
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
        id = "32g5Z4hY01WJbA0rYz7Zwx"
        fingerprint = "v1_sha256_fd5f0fbf71b7b53862aabda6e7130c3b1da0ed5dc7154a211872315acceb0ec1"
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
        all of them
}

rule Inject_Thread
{
    meta:
        id = "12Eh51OqqPAaMTCnkTlzBd"
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
        id = "6atyjGzTLfJ8iQDRD4djc6"
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
rule Process_Doppelganging
{
    meta:
        id = "5MoNUInHSpOmWgHQwsrBwk"
        fingerprint = "v1_sha256_33890ab1ba6b4bb53a96b63d348211edfc4f36433e59ce6927b27f4a6d8d473b"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee ATR - Thomas Roccia - @fr0gger_"
        description = "Detect Process Doppelganging"
        category = "INFO"
        reference = "https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf"
        mitre_id = "T1186"

    strings:
        $func1 = "CreateTransaction" nocase
        $func2 = "CreateFileTransacted" nocase
        $func3 = "WriteFile" nocase
        $func5 = "RollbackTransaction" nocase
        $func6 = "CreateProcess" nocase
        $func7 = "CreateProcessParameters"
    condition:
        uint16(0) == 0x5A4D and ($func1 or $func2 or $func5 or (all of them) or
        pe.imports("KtmW32.dll", "CreateTransaction") and
        pe.imports("Kernel32.dll", "CreateFileTransacted") and
        pe.imports("KtmW32.dll", "RollbackTransaction"))
}

rule PROPagate
{
    meta:
        id = "4ycd1BKqbu7JSgIWZvJ8I8"
        fingerprint = "v1_sha256_d2ac2883eb39dade0cf9728be6bed20ebecf847e68542a1b827a5f5144f6e193"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect Window Properties Modfication"
        category = "INFO"
        reference = "http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/"
        mitre_id = "T1055"

    strings:
        $func1 = "SetProp" nocase
        $func2 = "FindWindows" nocase
        $func3 = "GetProp" nocase
        $var1 = "UxSubclassInfo" nocase
        $var2 = "CC32SubclassInfo" nocase
    condition:
        uint16(0) == 0x5A4D and ($func1 and $func3 and ($var1 or $var2) or (all of them) or
        pe.imports("User32.dll", "SetProp") and
        pe.imports("User32.dll", "GetProp"))
}

rule Atom_Bombing
{
    meta:
        id = "4UvsVoZNrdfPA8fR1Q7Xag"
        fingerprint = "v1_sha256_c1f92f26c5ba9c7a2f7275be19027af6f17b2ed7ac91accaf84aca55cecda1f0"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect AtomBombing Injection"
        category = "INFO"
        reference = "https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows"
        mitre_id = "T1055"

    strings:
        $var1 = "GlobalAddAtom" nocase
        $var2 = "GlobalGetAtomName" nocase
        $var3 = "QueueUserAPC" nocase
        $var4 = "NtQueueApcThread" nocase
        $var5 = "NtSetContextThread" nocase
    condition:
        uint16(0) == 0x5A4D and (all of them or
        pe.imports("Kernel32.dll", "GlobalAddAtom") and
        pe.imports("Kernel32.dll", "GlobalGetAtomName") and
        pe.imports("Kernel32.dll", "QueueUserAPC"))
}

rule APC_Inject
{
    meta:
        id = "66EfbYIBLDCqxeWzHF3607"
        fingerprint = "v1_sha256_95802dd611a934cad826eb4e3f027c3331abac854bb1af4ffdde5e9298906f83"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect APC Injection"
        category = "INFO"
        mitre_id = "T1055"

   strings:
        $func1 = "NtQueueApcThread" nocase
        $func2 = "NtResumeThread" nocase
        $func3 = "NTTestAlert" nocase
        $func4 = "QueueUserApc" nocase
   condition:
        uint16(0) == 0x5A4D and ($func1 and $func2 or all of them)
}

rule CTRL_Inject
{
    meta:
        id = "7jorZ2Rxq03Vhq5Ko2Xop8"
        fingerprint = "v1_sha256_d13891339080101c981cd87313309cdc931782ef17ef55aecccfa8e6ab04b836"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect Control Inject"
        category = "INFO"
        reference = "https://blog.ensilo.com/ctrl-inject"
        mitre_id = "T1055"

   strings:
        $func1 = "OpenProcess" nocase
        $func2 = "VirtualAllocEx" nocase
        $func3 = "WriteProcessMemory" nocase
        $func4 = "EncodePointer" nocase
        $func5 = "EncodeRemotePointer" nocase
        $func6 = "SetProcessValidCallTargets" nocase
   condition:
        uint16(0) == 0x5A4D and ($func1 and $func2 and ($func4 or $func5) and $func6 or (all of them))

}
