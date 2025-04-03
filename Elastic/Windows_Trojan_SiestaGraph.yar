rule Windows_Trojan_SiestaGraph_8c36ddc1 {
    meta:
        id = "5gNTAngZsuH2PVn73aGRoL"
        fingerprint = "v1_sha256_17ce8090b88100f00c07df0599cd51dc7682f4c43de989ce58621df97eca42fb"
        version = "1.0"
        date = "2022-12-14"
        modified = "2022-12-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
        threat_name = "Windows.Trojan.SiestaGraph"
        reference_sample = "50c2f1bb99d742d8ae0ad7c049362b0e62d2d219b610dcf25ba50c303ccfef54"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "downloadAsync" ascii nocase fullword
        $a2 = "UploadxAsync" ascii nocase fullword
        $a3 = "GetAllDriveRootChildren" ascii fullword
        $a4 = "GetDriveRoot" ascii fullword
        $a5 = "sendsession" wide fullword
        $b1 = "ListDrives" wide fullword
        $b2 = "Del OK" wide fullword
        $b3 = "createEmailDraft" ascii fullword
        $b4 = "delMail" ascii fullword
    condition:
        all of ($a*) and 2 of ($b*)
}

rule Windows_Trojan_SiestaGraph_ad3fe5c6 {
    meta:
        id = "irQr1rqgR1eoydwBWE5mT"
        fingerprint = "v1_sha256_b625221b77803c2c052db09c90a76666cf9e0ae34cb0d59ae303e890e646e94b"
        version = "1.0"
        date = "2023-09-12"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
        threat_name = "Windows.Trojan.SiestaGraph"
        reference_sample = "fe8f99445ad139160a47b109a8f3291eef9c6a23b4869c48d341380d608ed4cb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "GetAllDriveRootChildren" ascii fullword
        $a2 = "GetDriveRoot" ascii fullword
        $a3 = "sendsession" wide fullword
        $b1 = "status OK" wide fullword
        $b2 = "upload failed" wide fullword
        $b3 = "Failed to fetch file" wide fullword
        $c1 = "Specified file doesn't exist" wide fullword
        $c2 = "file does not exist" wide fullword
    condition:
        6 of them
}

rule Windows_Trojan_SiestaGraph_d801ce71 {
    meta:
        id = "5ysQzRDo1ual2tqPke4vXh"
        fingerprint = "v1_sha256_c2d00d64d69cb5d24d76f6c551b49aa1acef1e1bab96f7ed7facc148244a8370"
        version = "1.0"
        date = "2023-09-12"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
        threat_name = "Windows.Trojan.SiestaGraph"
        reference_sample = "fe8f99445ad139160a47b109a8f3291eef9c6a23b4869c48d341380d608ed4cb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $hashgenfunc = { 02 2C ?? 20 [4] 0A 16 0B 2B ?? 02 07 6F [4] 06 61 20 [4] 5A 0A 07 17 58 0B 07 02 6F [4] 32 ?? }
        $sendpostfunc = { 72 [4] 72 [4] 72 [4] 02 73 [4] 73 [4] 28 [4] 0A 72 [4] 72 [4] 06 28 [4] 2A }
        $command15 = { 25 16 1F 3A 9D 6F [4] 17 9A 13 ?? 11 ?? 28 [4] 13 ?? 11 ?? 28 [4] 11 ?? 28 [4] 2C 33 28 [4] 28 [4] 6F [4] 6F [4] 11 ?? 28 [4] 09 7B [4] 18 9A 72 [4] 72 [4] 28 [4] 26 DE }
    condition:
        all of them
}

