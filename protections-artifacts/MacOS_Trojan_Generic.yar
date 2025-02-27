rule MacOS_Trojan_Generic_a829d361 {
    meta:
        id = "15LmaJloMQ17AhBmAEIjJC"
        fingerprint = "v1_sha256_70a954e8b44b1ce46f5ce0ebcf43b46e1292f0b8cdb46aa67f980d3c9b0a6f61"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Generic"
        reference_sample = "5b2a1cd801ae68a890b40dbd1601cdfeb5085574637ae8658417d0975be8acb5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { E7 81 6A 12 EA A8 56 6C 86 94 ED F6 E8 D7 35 E1 EC 65 47 BA 8E 46 2C A6 14 5F }
    condition:
        all of them
}

