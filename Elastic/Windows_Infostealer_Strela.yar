rule Windows_Infostealer_Strela_0dc3e4a1 {
    meta:
        id = "xNTNYQN28obxEcldd95Si"
        fingerprint = "v1_sha256_ac1b53f2857fd13ba0e33aa94c65f0d5fa22b76d504fff347b3ff0a53f37ee26"
        version = "1.0"
        date = "2024-03-25"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Infostealer.Strela"
        reference_sample = "e6991b12e86629b38e178fef129dfda1d454391ffbb236703f8c026d6d55b9a1"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "strela" fullword
        $s2 = "/server.php" fullword
        $s3 = "/out.php" fullword
        $s4 = "%s%s\\key4.db" fullword
        $s5 = "%s%s\\logins.json" fullword
        $s6 = "%s,%s,%s\n" fullword
        $old_pdb = "Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb" fullword
    condition:
        3 of ($s*) or $old_pdb
}

