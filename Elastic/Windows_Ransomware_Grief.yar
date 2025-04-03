rule Windows_Ransomware_Grief_9953339a {
    meta:
        id = "147jLA6rqX3B61Cdek0Zde"
        fingerprint = "v1_sha256_f99ea1e1f59dc2999659cbe649e76001dd7139b1438440717b60f081d1e99d70"
        version = "1.0"
        date = "2021-08-04"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Grief"
        reference_sample = "0864575d4f487e52a1479c61c2c4ad16742d92e16d0c10f5ed2b40506bbc6ca0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 65 64 73 63 6F 72 70 69 6F 71 65 6E 61 62 6C 65 54 72 61 6E 73 6C 61 74 65 2E 41 64 65 65 6D 65 64 59 00 5A 41 70 70 6C 69 63 61 74 69 6F 6E 65 69 74 68 65 72 33 34 2E 30 28 39 39 25 6D 65 6D 6F 72 79 2C 77 69 74 68 6F 75 74 00 66 6F 72 47 6F 6F 67 6C 65 6C 74 68 65 6D 6F 72 65 6D 77 61 73 00 39 32 41 6E 69 6E 65 74 68 65 75 48 73 74 61 62 6C 65 73 6F 66 66 69 63 69 61 6C 00 43 4B 76 65 72 73 69 6F 6E 46 71 74 68 65 63 6F 6D 70 61 6E 79 2C 74 6F 6E 2E 35 30 37 00 6E 69 6E 2D 70 61 67 65 44 73 63 61 6E 6E 69 6E 67 61 63 63 65 73 73 48 69 63 6F 6E 72 65 6D }
    condition:
        all of them
}

