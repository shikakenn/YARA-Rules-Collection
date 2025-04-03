rule MacOS_Cryptominer_Generic_d3f68e29 {
    meta:
        id = "1CTc6QY3k1K9MMtCJN0Qlv"
        fingerprint = "v1_sha256_cc336e536e0f8dda47f9551dfabfc50c2094fffe4a69cdcec23824dd063dede0"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "d9c78c822dfd29a1d9b1909bf95cab2a9550903e8f5f178edeb7a5a80129fbdb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = "command line argument. See 'ethminer -H misc' for details." ascii fullword
        $a2 = "Ethminer - GPU ethash miner" ascii fullword
        $a3 = "StratumClient"
    condition:
        all of them
}

rule MacOS_Cryptominer_Generic_365ecbb9 {
    meta:
        id = "6po6ZsJKojU1Dsi8rZIW8i"
        fingerprint = "v1_sha256_66f16c8694c5cfde1b5e4eea03c530fa32a15022fa35acdbb676bb696e7deae2"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 55 6E 6B 6E 6F 77 6E 20 6E 65 74 77 6F 72 6B 20 73 70 65 63 69 66 69 65 64 20 }
    condition:
        all of them
}

rule MacOS_Cryptominer_Generic_4e7d4488 {
    meta:
        id = "4F5Qy8QZd52ca8K08PUEz3"
        fingerprint = "v1_sha256_708b21b687c8b853a9b5f8a50d31119e4f0a02a5b63f81ba1cac8c06acd19214"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 69 73 20 66 69 65 6C 64 20 74 6F 20 73 68 6F 77 20 6E 75 6D 62 65 72 20 6F 66 }
    condition:
        all of them
}

