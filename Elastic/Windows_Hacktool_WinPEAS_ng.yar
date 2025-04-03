rule Windows_Hacktool_WinPEAS_ng_66197d54 {
    meta:
        id = "ODrhd8coQINRiY95AG119"
        fingerprint = "v1_sha256_7bccf37960e2f197bb0021ecb12872f0f715b674d9774d02ec4e396f18963029"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, application module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Possible DLL Hijacking, folder is writable" ascii wide
        $win_1 = "FolderPerms:.*" ascii wide
        $win_2 = "interestingFolderRights" ascii wide
        $win_3 = "(Unquoted and Space detected)" ascii wide
        $win_4 = "interestingFolderRights" ascii wide
        $win_5 = "RegPerms: .*" ascii wide
        $win_6 = "Permissions file: {3}" ascii wide
        $win_7 = "Permissions folder(DLL Hijacking):" ascii wide
    condition:
        4 of them
}

rule Windows_Hacktool_WinPEAS_ng_e8ed269c {
    meta:
        id = "2wEP5THHWlzy4WLOiqoAHd"
        fingerprint = "v1_sha256_c56b6dfb2c3ae657615c825a4d5d5640c2204fa4217262e1ccb4359d5a914a63"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, checks module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "systeminfo" ascii wide
        $win_1 = "Please specify a valid log file." ascii wide
        $win_2 = "argument present, redirecting output" ascii wide
        $win_3 = "max-regex-file-size" ascii wide
        $win_4 = "-lolbas" ascii wide
        $win_5 = "[!] the provided linpeas.sh url:" ascii wide
        $win_6 = "sensitive_files yaml" ascii wide
        $win_7 = "Getting Win32_UserAccount" ascii wide
        $win_8 = "(local + domain)" ascii wide
        $win_9 = "Creating AppLocker bypass" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_413caa6b {
    meta:
        id = "1IW0Q3CegENoaSNh1s66wd"
        fingerprint = "v1_sha256_4f2417d61be5e68630408a151cd73372aef9e7f4638acf4e80bfa5b2811119a7"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, event module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Interesting Events information" ascii wide
        $win_1 = "PowerShell events" ascii wide
        $win_2 = "Created (UTC)" ascii wide
        $win_3 = "Printing Account Logon Events" ascii wide
        $win_4 = "Subject User Name" ascii wide
        $win_5 = "Target User Name" ascii wide
        $win_6 = "NTLM relay might be possible" ascii wide
        $win_7 = "You can obtain NetNTLMv2" ascii wide
        $win_8 = "The following users have authenticated" ascii wide
        $win_9 = "You must be an administrator" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_23fee092 {
    meta:
        id = "ZziKOBevBzufQfp9myrVW"
        fingerprint = "v1_sha256_ed019c9198b5d9ff8392bfd7e0b23a7b1383eabce4c71c665a3ca4a943c8b6ee"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, File analysis module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "File Analysis" ascii wide
        $win_1 = "apache*" ascii wide
        $win_2 = "tomcat*" ascii wide
        $win_3 = "had a timeout (ReDoS avoided but regex" ascii wide
        $win_4 = "Error looking for regex" ascii wide
        $win_5 = "Looking for secrets inside" ascii wide
        $win_6 = "files with ext" ascii wide
        $win_7 = "(limited to" ascii wide
    condition:
        4 of them
}

rule Windows_Hacktool_WinPEAS_ng_861d3264 {
    meta:
        id = "3YYfk8gc2zicvwoBAT1Ug4"
        fingerprint = "v1_sha256_e6a0a0a24c70d69c0aa56063d2db0f5a0fedcda5b96d945ac14520524b1d00fd"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, File Info module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "ConsoleHost_history.txt" ascii wide
        $win_1 = "Interesting files and registry" ascii wide
        $win_2 = "Cloud Credentials" ascii wide
        $win_3 = "Accessed:{2} -- Size:{3}" ascii wide
        $win_4 = "Unattend Files" ascii wide
        $win_5 = "Looking for common SAM" ascii wide
        $win_6 = "Found installed WSL distribution" ascii wide
        $win_7 = "Check skipped, if you want to run it" ascii wide
        $win_8 = "Cached GPP Passwords" ascii wide
        $win_9 = "[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[pP][aA][sS][sS][wW][oO]" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_57587f8c {
    meta:
        id = "1KjCcGqYCGFa0xMNhO1w7T"
        fingerprint = "v1_sha256_175b8b6f9fca189f2fc41f1029ad512db2c8b0e52ea04bfbc3d410d355928ab9"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, Network module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Network Information" ascii wide
        $win_1 = "Network Shares" ascii wide
        $win_2 = "Permissions.*" ascii wide
        $win_3 = "Network Ifaces and known hosts" ascii wide
        $win_4 = "Enumerating IPv4 connections" ascii wide
        $win_5 = "Showing only DENY rules" ascii wide
        $win_6 = "File Permissions.*|Folder Permissions.*" ascii wide
        $win_7 = "DNS cached --limit" ascii wide
        $win_8 = "SELECT * FROM win32_networkconnection" ascii wide
        $win_9 = "Enumerating Internet settings," ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_cae025b1 {
    meta:
        id = "stGczwdJlBqKf6vwuYLRX"
        fingerprint = "v1_sha256_9c34443cffed43513242321e2170484dbb0d41b251aee8ea640d44da76918122"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, Process info module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Processes Information" ascii wide
        $win_1 = "Interesting Processes -non Microsoft-" ascii wide
        $win_2 = "Permissions:.*" ascii wide
        $win_3 = "Possible DLL Hijacking.*" ascii wide
        $win_4 = "ExecutablePath" ascii wide
        $win_5 = "Vulnerable Leaked Handlers" ascii wide
        $win_6 = "Possible DLL Hijacking folder:" ascii wide
        $win_7 = "Command Line:" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_4a9b9603 {
    meta:
        id = "6jEyFc1nv5iKbsMrWf6nW3"
        fingerprint = "v1_sha256_8d78483b54d3be6988b1f5df826b8709b7aa2045ff3a3e754c359365d053bb27"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, Services info module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Services Information" ascii wide
        $win_1 = "Interesting Services -non Microsoft-" ascii wide
        $win_2 = "FilteredPath" ascii wide
        $win_3 = "YOU CAN MODIFY THIS SERVICE:" ascii wide
        $win_4 = "Modifiable Services" ascii wide
        $win_5 = "AccessSystemSecurity" ascii wide
        $win_6 = "Looks like you cannot change the" ascii wide
        $win_7 = "Checking write permissions in" ascii wide
    condition:
        4 of them
}

rule Windows_Hacktool_WinPEAS_ng_4db2c852 {
    meta:
        id = "4CffVc6kN6HbUEHsCYLmNb"
        fingerprint = "v1_sha256_88c88103a055d25ba97f08e2f47881001ad8a2200a33ac04246494963dfe6638"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, System info module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "No prompting|PromptForNonWindowsBinaries" ascii wide
        $win_1 = "System Information" ascii wide
        $win_2 = "Showing All Microsoft Updates" ascii wide
        $win_3 = "GetTotalHistoryCount" ascii wide
        $win_4 = "PS history size:" ascii wide
        $win_5 = "powershell_transcript*" ascii wide
        $win_6 = "Check what is being logged" ascii wide
        $win_7 = "WEF Settings" ascii wide
        $win_8 = "CredentialGuard is active" ascii wide
        $win_9 = "cachedlogonscount is" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_bcedc8b2 {
    meta:
        id = "GeXHkeo0E9nKGsVMYuqLC"
        fingerprint = "v1_sha256_7f0a6a9168b5ff7cc02ccadd211cc8096307651be65c2b3e7cc9fdbbde08ab9f"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, User info module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Users Information" ascii wide
        $win_1 = "docker|Remote |DNSAdmins|AD Recycle Bin|" ascii wide
        $win_2 = "NotChange|NotExpi" ascii wide
        $win_3 = "Current Token privileges" ascii wide
        $win_4 = "Clipboard text" ascii wide
        $win_5 = "{0,-10}{1,-15}{2,-15}{3,-25}{4,-10}{5}" ascii wide
        $win_6 = "Ever logged users" ascii wide
        $win_7 = "Some AutoLogon credentials were found" ascii wide
        $win_8 = "Current User Idle Time" ascii wide
        $win_9 = "DsRegCmd.exe /status" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_b6bb3e7c {
    meta:
        id = "4vhfSqnND84gxvzzTzfnaT"
        fingerprint = "v1_sha256_e2eaf91b9c5d3616fb2f6f6bc4b44841b1efa3b4efe7ac72afe225728523af75"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the dotNet binary, Windows credentials module"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Windows Credentials" ascii wide
        $win_1 = "Checking Windows Vault" ascii wide
        $win_2 = "Identity.*|Credential.*|Resource.*" ascii wide
        $win_3 = "Checking Credential manager" ascii wide
        $win_4 = "Saved RDP connections" ascii wide
        $win_5 = "Recently run commands" ascii wide
        $win_6 = "Checking for DPAPI" ascii wide
        $win_7 = "Checking for RDCMan" ascii wide
        $win_8 = "Looking for saved Wifi credentials" ascii wide
        $win_9 = "Looking AppCmd.exe" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_94474b0b {
    meta:
        id = "4tp8hIZiXLVi8v4cVzxR5U"
        fingerprint = "v1_sha256_e209c9ce1f4b11c5fdeade3298329d62f5cf561403c87077d94b6921e81ffaea"
        version = "1.0"
        date = "2022-12-21"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "WinPEAS detection based on the bat script"
        category = "INFO"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $win_0 = "Windows local Privilege Escalation Awesome Script" ascii wide
        $win_1 = "BASIC SYSTEM INFO" ascii wide
        $win_2 = "LAPS installed?" ascii wide
        $win_3 = "Check for services restricted from the outside" ascii wide
        $win_4 = "CURRENT USER" ascii wide
        $win_5 = "hacktricks.xyz" ascii wide
        $win_6 = "SERVICE VULNERABILITIES" ascii wide
        $win_7 = "DPAPI MASTER KEYS" ascii wide
        $win_8 = "Files in registry that may contain credentials" ascii wide
        $win_9 = "SAM and SYSTEM backups" ascii wide
    condition:
        6 of them
}

