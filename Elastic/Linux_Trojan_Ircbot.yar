rule Linux_Trojan_Ircbot_bb204b81 {
    meta:
        id = "5uWR7o2SBciqMzHUlNQyMu"
        fingerprint = "v1_sha256_90d211c11281f5f8832210f3fc087fe5ff5a519b9b38628835e8b5fcc560bd9b"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ircbot"
        reference_sample = "6147481d083c707dc98905a1286827a6e7009e08490e7d7c280ed5a6356527ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 44 C8 4C 5E F8 8D EF 80 83 CD FF 31 DB 30 22 }
    condition:
        all of them
}

rule Linux_Trojan_Ircbot_7c60454d {
    meta:
        id = "7iLftF0uwatMXquG3TDC3"
        fingerprint = "v1_sha256_90dcd0a3d3f6345e66db0a4f8465e3830eb4e3bcb675db16c60a89e20f935aec"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ircbot"
        reference_sample = "14eeff3516de6d2cb11d6ada4026e3dcee1402940e3a0fb4fa224a5c030049d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 49 89 F0 41 54 55 48 89 CD 53 48 89 FB 48 83 EC 58 48 85 D2 }
    condition:
        all of them
}

