rule Linux_Trojan_Mechbot_f2e1c5aa {
    meta:
        id = "2odWtuDGB0Ov6wiNMlyNKe"
        fingerprint = "v1_sha256_2ba9ece1ab2360702a59a737a20b6dbd8fca276b543477f9290ab80c6f51e2f1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mechbot"
        reference_sample = "5f8e80e6877ff2de09a12135ee1fc17bee8eb6d811a65495bcbcddf14ecb44a3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 52 56 45 52 00 42 41 4E 4C 49 53 54 00 42 4F 4F 54 00 42 }
    condition:
        all of them
}

