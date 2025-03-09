/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule Detect_Monitoring 
{
    meta:
        id = "22XRRfjNadNmtXg1GnUjkY"
        fingerprint = "v1_sha256_1cbdae26ab70f61def1e8934b2c14a5e181660c8c5d090893896fc38fec9a2ab"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        description = "Check for monitoring tools"
        category = "INFO"

    strings:
        $var1 = "procexp.exe" nocase
        $var2 = "fiddler.exe" nocase
        $var3 = "winhex.exe" nocase      
        $var4 = "procmon.exe" nocase
        $var5 = "processmonitor.exe" nocase
        $var6 = "wireshark.exe" nocase
        $var7 = "processhacker.exe" nocase
        $var8 = "hiew32.exe" nocase

        $reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $val = "DisableTaskMgr" 

    condition:
        any of ($var*) or $reg and $val
}

rule Disable_Registry 
{
    meta:
        id = "6xt8yOESbChOI1uxC4XAju"
        fingerprint = "v1_sha256_16865c31a735e4f79418be56220d1e58b0a3c9bff8d9fdf2b8c4529fa14a4cb1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Disable Registry editor"
        category = "INFO"

    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue" 
        $r1 = "DisableRegistryTools" 
        $r2 = "DisableRegedit" 
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}
