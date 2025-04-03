rule Windows_Ransomware_Ragnarok_1cab7ea1 : beta {
    meta:
        id = "6Snq4TzhQNbxgIfOyqfhdf"
        fingerprint = "v1_sha256_8bae3ea4304473209fc770673b680154bf227ce30f6299101d93fe830da0fe91"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RAGNAROK ransomware"
        category = "INFO"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        threat_name = "Windows.Ransomware.Ragnarok"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1 = ".ragnarok" ascii wide fullword
    condition:
        1 of ($c*)
}

rule Windows_Ransomware_Ragnarok_7e802f95 : beta {
    meta:
        id = "1CQt6KDt4ETY9tWoNHTdRg"
        fingerprint = "v1_sha256_8f293cdbdc3c395e18c304dfa43d0dcdb52b18bde5b5d084190ceec70aea6cbd"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RAGNAROK ransomware"
        category = "INFO"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        threat_name = "Windows.Ransomware.Ragnarok"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $d1 = { 68 04 94 42 00 FF 35 A0 77 43 00 }
        $d2 = { 68 90 94 42 00 FF 35 A0 77 43 00 E8 8F D6 00 00 8B 40 10 50 }
    condition:
        1 of ($d*)
}

rule Windows_Ransomware_Ragnarok_efafbe48 : beta {
    meta:
        id = "4x6VlLLHdMk56TV7vjwUZv"
        fingerprint = "v1_sha256_c9d203620e0e6e04d717595ca70a5e5efa74abfc11e4e732d729caab2d246c27"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RAGNAROK ransomware"
        category = "INFO"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        threat_name = "Windows.Ransomware.Ragnarok"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "cmd_firewall" ascii fullword
        $a2 = "cmd_recovery" ascii fullword
        $a3 = "cmd_boot" ascii fullword
        $a4 = "cmd_shadow" ascii fullword
        $a5 = "readme_content" ascii fullword
        $a6 = "readme_name" ascii fullword
        $a8 = "rg_path" ascii fullword
        $a9 = "cometosee" ascii fullword
        $a10 = "&prv_ip=" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Ransomware_Ragnarok_5625d3f6 : beta {
    meta:
        id = "2xl8czEIJ7zYjeVQjhE31s"
        fingerprint = "v1_sha256_8c22cf9dfbeba7391f6d2370c88129650ef4c778464e676752de1d0fd9c5b34e"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RAGNAROK ransomware"
        category = "INFO"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        threat_name = "Windows.Ransomware.Ragnarok"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b1 = "prv_ip" ascii fullword
        $b2 = "%i.%i.%i" ascii fullword
        $b3 = "pub_ip" ascii fullword
        $b4 = "cometosee" ascii fullword
    condition:
        all of ($b*)
}

