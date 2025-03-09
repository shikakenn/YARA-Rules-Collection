/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule disable_antivirus 
{
    meta:
        id = "2xGVTedsU1YjrnZ4FJb9PT"
        fingerprint = "v1_sha256_0913383037ee7f947ba32441919ad3cc1b7cd511f075d6c046a5dc205278f1fc"
        version = "1.0"
        modified = "2025-03-10"
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

rule disable_uac {
    meta:
        id = "5LXp5xrApGH0pK9zTOjyFZ"
        fingerprint = "v1_sha256_52143095104bcbf8b5230a633f68b6e27460b49bcc870eb4c9e040caf7aab93a"
        version = "1.0"
        modified = "2025-03-10"
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

rule disable_firewall {
    meta:
        id = "7hyUOTEqEUhYnPsixY1Qq4"
        fingerprint = "v1_sha256_f00ceaa562294dbde0848d598abf692b0874716f6ae3264354b57d87b04d03d8"
        version = "1.0"
        modified = "2025-03-10"
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
