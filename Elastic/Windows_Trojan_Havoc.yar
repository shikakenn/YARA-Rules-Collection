rule Windows_Trojan_Havoc_77f3d40e {
    meta:
        id = "70jjjyObGmD1QA4uhkYD1Z"
        fingerprint = "v1_sha256_3d2733ed24d90e9e851ec36a08c497e9c90b47c3dcbb8755e3f6b6a6bd3a8b54"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Havoc"
        reference_sample = "3427dac129b760a03f2c40590c01065c9bf2340d2dfa4a4a7cf4830a02e95879"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $core = { 48 ?? ?? 2C 06 00 00 00 ?? ?? 48 ?? ?? 5C 06 00 00 00 ?? ?? ?? ?? ?? ?? 48 8B ?? 5C 06 00 00 ?? F6 99 5A 2E E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 4C 02 00 00 48 8B ?? 5C 06 00 00 ?? 23 DB 07 03 E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 44 02 00 00 48 8B ?? 5C 06 00 00 ?? DA 81 B3 C0 E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 54 02 00 00 48 8B ?? 5C 06 00 00 ?? D7 71 BA 70 E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 64 02 00 00 48 8B ?? 5C 06 00 00 ?? 88 2B 49 8E E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 84 02 00 00 48 8B ?? 5C 06 00 00 ?? EF F0 A1 3A E8 ?? ?? ?? ?? }
        $commands_table = { 0B 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 64 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 15 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 10 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 0C 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? [0-12] 0F 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 01 20 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 03 20 00 00 ?? ?? ?? ?? ?? ?? ?? ?? C4 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? CE 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? D8 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 34 08 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 16 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 18 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 1A 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 28 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 5C 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
        $hashes_0 = { F6 99 5A 2E }
        $hashes_1 = { DA 81 B3 C0 }
        $hashes_2 = { D7 71 BA 70 }
        $hashes_3 = { 88 2B 49 8E }
        $hashes_4 = { EF F0 A1 3A }
        $hashes_5 = { F5 39 34 7C }
        $hashes_6 = { 2A 92 12 D8 }
        $hashes_7 = { 8D F1 4F 84 }
        $hashes_8 = { 5B BC CE 73 }
        $hashes_9 = { 59 24 93 B8 }
        $hashes_10 = { 02 9E D0 C2 }
        $hashes_11 = { E5 36 26 AE }
        $hashes_12 = { 5C 3C B4 F3 }
        $hashes_13 = { 2F 87 D8 1C }
        $hashes_14 = { D7 53 22 AC }
    condition:
        $core or ($commands_table and all of ($hashes*))
}

rule Windows_Trojan_Havoc_9c7bb863 {
    meta:
        id = "2dNkRoITQu1ww0sExMrrSi"
        fingerprint = "v1_sha256_c1245c38c54b0a72fb335680d9ea191390e4e2fe7e47a3ed776878c5e01a3e16"
        version = "1.0"
        date = "2023-04-28"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Havoc"
        reference_sample = "261b92d9e8dcb9d0abf1627b791831ec89779f2b7973b1926c6ec9691288dd57"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 56 48 89 E6 48 83 E4 F0 48 83 EC 20 E8 0F 00 00 00 48 89 F4 5E C3 }
        $a2 = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_Havoc_88053562 {
    meta:
        id = "7QXN3ib24rK42rlCo0Rchn"
        fingerprint = "v1_sha256_f79b39cc2ca4bbf6ad4b6585a9914a75797110d6fb68bcb7141c5c3d0429c412"
        version = "1.0"
        date = "2024-01-04"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Havoc"
        reference_sample = "2f0b59f8220edd0d34fba92905faf0b51aead95d53be8b5f022eed7e21bdb4af"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 81 EC F8 04 00 00 48 8D 7C 24 78 44 89 8C 24 58 05 00 00 48 8B AC 24 60 05 00 00 4C 8D 6C 24 78 F3 AB B9 59 00 00 00 48 C7 44 24 70 00 00 00 00 C7 44 24 78 68 00 00 00 C7 84 24 B4 00 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_Havoc_ffecc8af {
    meta:
        id = "7AEFYmZ7JNrY5ZvUowsrcy"
        fingerprint = "v1_sha256_c9da6215db1de91a6cd52dd6558dc5a60bbd69abc6fa0db8714f001cdae20ddb"
        version = "1.0"
        date = "2024-04-29"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Havoc"
        reference_sample = "495d323651c252e38814b77b9c6c913b9489e769252ac8bbaf8432f15e0efe44"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $commands_table = { 0B 00 00 00 00 00 00 00 [8] 64 00 00 00 00 00 00 00 [8] 15 00 00 00 00 00 00 00 [8] 10 10 00 00 00 00 00 00 [8] 0C 00 00 00 00 00 00 00 [8] 0F 00 00 00 00 00 00 00 [8] 14 00 00 00 00 00 00 00 [8] 01 20 00 00 00 00 00 00 [8] 03 20 00 00 00 00 00 00 [8] C4 09 00 00 00 00 00 00 [8] CE 09 00 00 00 00 00 00 [8] D8 09 00 00 00 00 00 00 [8] 34 08 00 00 00 00 00 00 [8] 16 00 00 00 00 00 00 00 [8] 18 00 00 00 00 00 00 00 [8] 1A 00 00 00 00 00 00 00 [8] 28 00 00 00 00 00 00 00 [8] E2 09 00 00 00 00 00 00 [8] EC 09 00 00 00 00 00 00 [8] F6 09 00 00 00 00 00 00 [8] 00 0A 00 00 00 00 00 00 [8] 5C 00 00 00 00 00 00 00 }
        $hash_ldrloaddll = { 43 6A 45 9E }
        $hash_ldrgetprocedureaddress = { B6 6B CE FC }
        $hash_ntaddbootentry = { 76 C7 FC 8C }
        $hash_ntallocatevirtualmemory = { EC B8 83 F7 }
        $hash_ntfreevirtualmemory = { 09 C6 02 28 }
        $hash_ntunmapviewofsection = { CD 12 A4 6A }
        $hash_ntwritevirtualmemory = { 92 01 17 C3 }
        $hash_ntsetinformationvirtualmemory = { 39 C2 6A 94 }
        $hash_ntqueryvirtualmemory = { 5D E8 C0 10 }
        $hash_ntopenprocesstoken = { 99 CA 0D 35 }
        $hash_ntopenthreadtoken = { D2 47 33 80 }
    condition:
        $commands_table and 4 of ($hash_*)
}

