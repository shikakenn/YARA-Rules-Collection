rule Windows_Cryptominer_Generic_dd1e4d1a {
    meta:
        id = "1C9vNHOQ6GTKV9k2HbXw0v"
        fingerprint = "v1_sha256_b7289c4688ec67d59e67755461f1f4e0c3f47ef9f8c73fc1dcc1d168baf11623"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Cryptominer.Generic"
        reference_sample = "7ac1d7b6107307fb2442522604c8fa56010d931392d606ac74dcea6b7125954b"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { EF F9 66 0F EF FA 66 0F FE FE 66 0F 6F B0 B0 00 00 00 66 0F }
    condition:
        all of them
}

rule Windows_Cryptominer_Generic_f53cfb9b {
    meta:
        id = "4p4zCqnH5sRCWEb3FXMdCw"
        fingerprint = "v1_sha256_b2453862747e251afc34c57e887889b8d3a65a9cc876d4a95ff5ecfcc24e4bd3"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Cryptominer.Generic"
        reference_sample = "a9870a03ddc6543a5a12d50f95934ff49f26b60921096b2c8f2193cb411ed408"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 81 EC B8 00 00 00 0F AE 9C 24 10 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F AE 94 24 14 01 00 00 4C 8B A9 E0 00 00 00 4C 8B CA 4C 8B 51 20 4C 8B C1 4C 33 11 ?? ?? ?? ?? ?? ?? 4C 8B 59 28 }
    condition:
        all of them
}

