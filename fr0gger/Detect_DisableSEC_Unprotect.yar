/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule Disable_Antivirus 
{
    meta:
        id = "5pddapYEsWtyQ6nRVNSZDf"
        fingerprint = "v1_sha256_0913383037ee7f947ba32441919ad3cc1b7cd511f075d6c046a5dc205278f1fc"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Disable AntiVirus"
        category = "INFO"

    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase

        $c1 = "RegSetValue" 

        $r1 = "AntiVirusDisableNotify" 
        $r2 = "DontReportInfectionInformation" 
        $r3 = "DisableAntiSpyware" 
        $r4 = "RunInvalidSignatures" 
        $r5 = "AntiVirusOverride" 
        $r6 = "CheckExeSignatures"

        $f1 = "blackd.exe" nocase
        $f2 = "blackice.exe" nocase
        $f3 = "lockdown.exe" nocase
        $f4 = "lockdown2000.exe" nocase
        $f5 = "taskkill.exe" nocase
        $f6 = "tskill.exe" nocase
        $f7 = "smc.exe" nocase
        $f8 = "sniffem.exe" nocase
        $f9 = "zapro.exe" nocase
        $f10 = "zlclient.exe" nocase
        $f11 = "zonealarm.exe" nocase

    condition:
        ($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}

rule Disable_UAC 
{
    meta:
        id = "6jBtVpPG9mVpYmsfvN7Q0p"
        fingerprint = "v1_sha256_52143095104bcbf8b5230a633f68b6e27460b49bcc870eb4c9e040caf7aab93a"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Disable User Access Control"
        category = "INFO"

    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule Disable_Firewall 
{
    meta:
        id = "2QwPRJ0iibsfVmfm4VRmnn"
        fingerprint = "v1_sha256_f00ceaa562294dbde0848d598abf692b0874716f6ae3264354b57d87b04d03d8"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Disable Firewall"
        category = "INFO"

    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue" 
        $r1 = "FirewallPolicy" 
        $r2 = "EnableFirewall" 
        $r3 = "FirewallDisableNotify" 
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule Disable_Dep 
{
    meta:
        id = "2KfLTbkV5MkcI037M87rhc"
        fingerprint = "v1_sha256_6c291960ea8febc4b089bdd424ee89c91b4c6ef726f7c74eb6ac90c2afc97cf3"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Bypass DEP"
        category = "INFO"

    strings:
        $c1 = "EnableExecuteProtectionSupport" 
        $c2 = "NtSetInformationProcess" 
        $c3 = "VirtualProctectEx" 
        $c4 = "SetProcessDEPPolicy" 
        $c5 = "ZwProtectVirtualMemory" 
    condition:
        any of them
}

rule Inject_Certificate 
{
    meta:
        id = "1K93tKtertN2ivoHGRi52k"
        fingerprint = "v1_sha256_515beb34af74e6944163d5485c540681a951bc9cbfcb7c76d2b31dcfb1f9a1fa"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Inject certificate in store"
        category = "INFO"

    strings:
        $f1 = "Crypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
        $c1 = "CertOpenSystemStore" 
    condition:
    all of them
}

rule Escalate_Priv 
{
    meta:
        id = "5BRjVe4C6Tre5TN6BLyCMH"
        fingerprint = "v1_sha256_da1d9d9de26088342857db37a80d38a920a4e55543c3c9a1382b59f4a8754474"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Escalade priviledges"
        category = "INFO"

    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege" 
        $c2 = "AdjustTokenPrivileges" 
    condition:
        1 of ($d*) and 1 of ($c*)
}
