rule Windows_Trojan_DustyWarehouse_a6cfc9f7 {
    meta:
        id = "4prrDoX2CSCqgo6iKtR2Np"
        fingerprint = "v1_sha256_2b4cd9316e2fda882c95673edecb9c82a03ef4fdcc2d2e25783644cc5dfb5bf0"
        version = "1.0"
        date = "2023-08-25"
        modified = "2023-11-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DustyWarehouse"
        reference_sample = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%4d.%2d.%2d-%2d:%2d:%2d" wide fullword
        $a2 = ":]%d-%d-%d %d:%d:%d" wide fullword
        $a3 = "\\sys.key" wide fullword
        $a4 = "[rwin]" wide fullword
        $a5 = "Software\\Tencent\\Plugin\\VAS" fullword
    condition:
        3 of them
}

rule Windows_Trojan_DustyWarehouse_3fef514b {
    meta:
        id = "2kP4P2FLTB9wG7u0UgxAV4"
        fingerprint = "v1_sha256_865ea1e54950a465b71939a41f7a726ccddcfa9f0d777ea853926f65bca0da84"
        version = "1.0"
        date = "2024-05-30"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DustyWarehouse"
        reference_sample = "4ad024f53595fdd380f5b5950b62595cd47ac424d2427c176a7b2dfe4e1f35f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 83 EC 30 48 C7 44 24 20 FE FF FF FF 48 89 5C 24 48 48 89 74 24 50 C7 44 24 40 [4] 48 8B 39 48 8B 71 08 48 8B 59 10 48 8B 49 18 ?? ?? ?? ?? ?? ?? 84 DB 74 05 E8 E1 01 00 00 48 8B CE }
    condition:
        all of them
}

