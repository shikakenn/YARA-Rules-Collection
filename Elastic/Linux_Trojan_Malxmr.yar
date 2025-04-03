rule Linux_Trojan_Malxmr_7054a0d0 {
    meta:
        id = "3SComlhQ3xY5EzhUQsVxpE"
        fingerprint = "v1_sha256_f7153fb11e0e4bf422021cc0fab99536c2a193198bf70d7f2af2fa5c1971c028"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Malxmr"
        reference_sample = "3a6b3552ffac13aa70e24fef72b69f683ac221105415efb294fb9a2fc81c260a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6E 64 47 56 7A 64 48 52 6C 63 33 52 30 5A 58 4E 30 64 47 56 }
    condition:
        all of them
}

rule Linux_Trojan_Malxmr_144994a5 {
    meta:
        id = "2c8DXifS0fv62lqql34c1"
        fingerprint = "v1_sha256_4d40337895e63d3dc6f0d94889863f0f5017533658210b902b08d84cf3588cab"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Malxmr"
        reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 78 71 51 58 5A 5A 4D 31 5A 35 59 6B 4D 78 61 47 4A 58 55 54 4A }
    condition:
        all of them
}

