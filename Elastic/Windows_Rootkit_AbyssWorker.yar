rule Windows_Rootkit_AbyssWorker_4ef8536c {
    meta:
        id = "3VpGZRLwElhUcVLIUHfLpX"
        fingerprint = "v1_sha256_ff38c6cd362abd59448640996af4207cf98673e5cea98d24d74d9378a0c1496d"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Rootkit.AbyssWorker"
        reference_sample = "6a2a0f9c56ee9bf7b62e1d4e1929d13046cd78a93d8c607fe4728cc5b1e8d050"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "7N6bCAoECbItsUR5-h4Rp2nkQxybfKb0F-wgbJGHGh20pWUuN1-ZxfXdiOYps6HTp0X" wide fullword
        $a2 = "\\??\\fqg0Et4KlNt4s1JT" wide fullword
        $a3 = "\\device\\czx9umpTReqbOOKF" wide fullword
        $a4 = { 48 35 04 82 66 00 48 8B 4C 24 28 48 81 F1 17 24 53 00 48 03 C1 48 89 04 24 48 8B 04 24 48 C1 E0 05 48 8B 0C 24 48 C1 E9 1B 48 0B C1 }
        $a5 = { 48 35 04 82 66 00 48 8B 4C 24 08 48 0F AF C8 48 8B C1 48 8B 4C 24 08 48 81 E1 17 24 53 00 48 03 C1 }
    condition:
        2 of ($a*)
}

