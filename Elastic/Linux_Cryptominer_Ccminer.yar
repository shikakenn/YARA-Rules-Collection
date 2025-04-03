rule Linux_Cryptominer_Ccminer_18fc60e5 {
    meta:
        id = "rinYv4bEyW63MhlkF33N8"
        fingerprint = "v1_sha256_75db45ccbeb558409ee9398065591472d4aee0382be5980adb9d0fb41e557789"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Ccminer"
        reference_sample = "dbb403a00c75ef2a74b41b8b58d08a6749f37f922de6cc19127a8f244d901c60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 68 27 52 22 02 02 32 22 22 03 5C 8B AE 00 00 00 48 03 5C }
    condition:
        all of them
}

rule Linux_Cryptominer_Ccminer_3c593bc3 {
    meta:
        id = "19CRD43SN8gLzr6pJMaNAA"
        fingerprint = "v1_sha256_94a0d33b474b3c60e926eaf06147eb0fdc56beac525f25326448bf2a5177d9c0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Ccminer"
        reference_sample = "dbb403a00c75ef2a74b41b8b58d08a6749f37f922de6cc19127a8f244d901c60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 83 5C DE C2 00 00 00 68 03 5C EB EA 00 00 00 48 03 1C DC }
    condition:
        all of them
}

