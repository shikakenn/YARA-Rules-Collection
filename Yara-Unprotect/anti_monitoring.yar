rule disable_firewall {
    meta:
        id = "3LgSojyL3vr7QRep9y6zWZ"
        fingerprint = "v1_sha256_f00ceaa562294dbde0848d598abf692b0874716f6ae3264354b57d87b04d03d8"
        version = "0.1"
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

rule disable_registry {
    meta:
        id = "13Xs60mRqqkFuUZPSVNbb7"
        fingerprint = "v1_sha256_16865c31a735e4f79418be56220d1e58b0a3c9bff8d9fdf2b8c4529fa14a4cb1"
        version = "0.1"
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

rule disable_dep {
    meta:
        id = "1kyuh5sJmeQwtA6XpPyom6"
        fingerprint = "v1_sha256_6c291960ea8febc4b089bdd424ee89c91b4c6ef726f7c74eb6ac90c2afc97cf3"
        version = "0.1"
        modified = "2025-03-10"
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

rule disable_taskmanager {
    meta:
        id = "1n6IQwvASPmGqF3hGiL3i6"
        fingerprint = "v1_sha256_78857f156876011146f4a9935dde48eb43c820a648d6ef650bc0d011852a8ed0"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Disable Task Manager"
        category = "INFO"

    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr"
    condition:
        1 of ($p*) and 1 of ($r*)
}
rule check_patchlevel {
    meta:
        id = "5SzwtKVqH7cT68Pxc6Cv6x"
        fingerprint = "v1_sha256_9dcada24652f5612abdb1bf7b837b4af8a3c8d7f829ec86aa6628c68744b36fd"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Check if hotfix are applied"
        category = "INFO"

    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}
rule win_token {
    meta:
        id = "7UZKePxYVRl8jJdakGssnB"
        fingerprint = "v1_sha256_022e70b66bf9193caaefe186eed88d40d3f5ba915d54cc3fdbde5201b2a5aaec"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Affect system token"
        category = "INFO"

    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "DuplicateTokenEx"
        $c2 = "AdjustTokenPrivileges"
        $c3 = "OpenProcessToken"
        $c4 = "LookupPrivilegeValueA"
    condition:
        $f1 and 1 of ($c*)
}
rule escalate_priv {
    meta:
        id = "7VGlIUj4PXV553PbCUk5Li"
        fingerprint = "v1_sha256_da1d9d9de26088342857db37a80d38a920a4e55543c3c9a1382b59f4a8754474"
        version = "0.1"
        modified = "2025-03-10"
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
