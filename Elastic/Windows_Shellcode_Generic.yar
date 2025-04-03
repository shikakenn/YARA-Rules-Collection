rule Windows_Shellcode_Generic_8c487e57 {
    meta:
        id = "1DPXdeRrXYODAJPKsvN8x9"
        fingerprint = "v1_sha256_a86ea8e15248e83ce7322c10e308a5a24096b1d7c67f5673687563dec8229dfe"
        version = "1.0"
        date = "2022-05-23"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Shellcode.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 }
    condition:
        all of them
}

rule Windows_Shellcode_Generic_f27d7beb {
    meta:
        id = "2hAj3gtewQ0iPY1kJZUVfS"
        fingerprint = "v1_sha256_8530a74a002d0286711cd86545aff0bf853de6b6684473b6211d678797c3639f"
        version = "1.0"
        date = "2022-06-08"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Shellcode.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 53 48 89 E3 66 83 E4 00 48 B9 [8] BA 01 00 00 00 41 B8 00 00 00 00 48 B8 [8] FF D0 48 89 DC 5B C3 }
    condition:
        all of them
}

rule Windows_Shellcode_Generic_29dcbf7a {
    meta:
        id = "BQCMXecFC8VU5hziVwSy5"
        fingerprint = "v1_sha256_c2a81cc27e696a2e488df7d2f96784bbaed83df5783efab312fc5ccbfd524b43"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Shellcode.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { FC 48 83 E4 F0 41 57 41 56 41 55 41 54 55 53 56 57 48 83 EC 40 48 83 EC 40 48 83 EC 40 48 89 E3 }
    condition:
        all of them
}

