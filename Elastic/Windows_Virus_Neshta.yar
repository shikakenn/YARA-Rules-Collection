rule Windows_Virus_Neshta_2a5a14c8 {
    meta:
        id = "CTa1PAMq55La4y52s6xli"
        fingerprint = "v1_sha256_0b5d0603f4c20a2368f697dd84cfe1790a5d0e5904c76066601c9e3d1b5ed1e1"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Virus.Neshta"
        reference_sample = "f298214764ee9ab690cb4b376d8a7893edcd9c05a3c4e6f3a56010974a130bd7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 44 65 6C 70 68 69 2D 74 68 65 20 62 65 73 74 2E 20 46 75 63 6B 20 6F 66 66 20 61 6C 6C 20 74 68 65 20 72 65 73 74 2E 20 4E 65 73 68 74 61 20 31 2E 30 20 4D 61 64 65 20 69 6E 20 42 65 6C 61 72 75 73 2E }
        $a2 = { 55 8B EC 81 C4 64 FF FF FF 53 56 57 33 D2 89 95 64 FF FF FF 8B F8 33 C0 55 68 FC 6D 40 00 64 FF 30 64 89 20 8D 85 69 FF FF FF 50 68 97 00 00 00 E8 1B D3 FF FF 33 DB EB 5C 8B F3 81 E6 FF 00 00 }
    condition:
        any of them
}

