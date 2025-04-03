rule Windows_Shellcode_Rdi_edc62a10 {
    meta:
        id = "7QW4qv76MGEI42jhm8LWtY"
        fingerprint = "v1_sha256_986cb6c28d2d9767a2fd084fdd71edb7a1c36e78ddedf3c562076cf6f5b5afd1"
        version = "1.0"
        date = "2023-06-23"
        modified = "2023-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Shellcode.Rdi"
        reference_sample = "64485ffc283e981c8b77db5a675c7ba2a04d3effaced522531185aa46eb6a36b"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00 BA [10] 00 41 B9 04 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 C7 }
    condition:
        all of them
}

rule Windows_Shellcode_Rdi_eee75d2c {
    meta:
        id = "kfD7dmMall6v3p5n4oSBw"
        fingerprint = "v1_sha256_18cd9be4af210686872610f832ac0ad58a48588a1226fc6093348ceb8371c6b4"
        version = "1.0"
        date = "2023-08-25"
        modified = "2023-11-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Shellcode.Rdi"
        reference_sample = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 81 EC 14 01 00 00 53 55 56 57 6A 6B 58 6A 65 66 89 84 24 CC 00 00 00 33 ED 58 6A 72 59 6A 6E 5B 6A 6C 5A 6A 33 }
    condition:
        all of them
}

rule Windows_Shellcode_Rdi_918f8e2f {
    meta:
        id = "lleoP7d2cMi4e9ReVCsT3"
        fingerprint = "v1_sha256_f3859d96000b4cfcdd9c3c6ef0d5674e1de51817de46659be0b57de46aaf6fdb"
        version = "1.0"
        date = "2025-01-15"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Shellcode.Rdi"
        reference_sample = "d8dab346c6235426e6119f8eb6bf81cafda8fb8ea88b86205e34d9c369b3b746"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a64 = { E8 00 00 00 00 59 49 89 C8 BA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 48 89 4C 24 28 }
        $a32 = { E8 00 00 00 00 58 55 89 E5 89 C2 81 C2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 05 00 00 00 83 C4 14 C9 C3 }
    condition:
        any of them
}

