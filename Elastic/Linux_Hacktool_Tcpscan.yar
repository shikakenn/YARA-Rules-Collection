rule Linux_Hacktool_Tcpscan_334d0ca5 {
    meta:
        id = "5gNRycbFEOAJyTgsfD1oFm"
        fingerprint = "v1_sha256_94ee723c660294e35caec5a2b66eeea64896265cfebc839ed3f55cf8f8c67d7e"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Tcpscan"
        reference_sample = "62de04185c2e3c22af349479a68ad53c31b3874794e7c4f0f33e8d125c37f6b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C4 10 89 45 D4 83 7D D4 00 79 1A 83 EC 0C 68 13 }
    condition:
        all of them
}

