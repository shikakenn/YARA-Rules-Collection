rule Windows_Ransomware_Pandora_bca8ce23 {
    meta:
        id = "6QlLualhPWOsdBw6zCfA2M"
        fingerprint = "v1_sha256_52203c1af994667ba6833defe547e886dd02167e4d76c57711080e3be0473bfc"
        version = "1.0"
        date = "2022-03-14"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Pandora"
        reference_sample = "2c940a35025dd3847f7c954a282f65e9c2312d2ada28686f9d1dc73d1c500224"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "/c vssadmin.exe delete shadows /all /quiet" wide fullword
        $a2 = "\\Restore_My_Files.txt" wide fullword
        $a3 = ".pandora" wide fullword
    condition:
        all of them
}

