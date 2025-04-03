rule Windows_Trojan_Guloader_8f10fa66 {
    meta:
        id = "3UmzWNgPr7ZqonlpmuQH1u"
        fingerprint = "v1_sha256_f2cd08f6a32c075dc0294a0e26c51e686babc54ced4faa1873368c8821f0bfef"
        version = "1.0"
        date = "2021-08-17"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/getting-gooey-with-guloader-downloader"
        threat_name = "Windows.Trojan.Guloader"
        reference_sample = "a3e2d5013b80cd2346e37460753eca4a4fec3a7941586cc26e049a463277562e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "msvbvm60.dll" wide fullword
        $a2 = "C:\\Program Files\\qga\\qga.exe" ascii fullword
        $a3 = "C:\\Program Files\\Qemu-ga\\qemu-ga.exe" ascii fullword
        $a4 = "USERPROFILE=" wide fullword
        $a5 = "Startup key" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Guloader_c4d9dd33 {
    meta:
        id = "3iBFqZ9O07TPG2RxKLD3I1"
        fingerprint = "v1_sha256_623ea751fc32648720bda40598024d4d5b6a9a11b3cce3c9427310ba17745643"
        version = "1.0"
        date = "2021-08-17"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/getting-gooey-with-guloader-downloader"
        threat_name = "Windows.Trojan.Guloader"
        reference_sample = "a3e2d5013b80cd2346e37460753eca4a4fec3a7941586cc26e049a463277562e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "This program cannot be run under virtual environment or debugging software !" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Guloader_2f1e44c8 {
    meta:
        id = "lqNpOF8glud0LdAgcfu9R"
        fingerprint = "v1_sha256_434b33c3fdc6bf4b0f59cd4aba66327d0b7ab524be603b256494d46b609cecd5"
        version = "1.0"
        date = "2023-10-30"
        modified = "2023-11-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/getting-gooey-with-guloader-downloader"
        threat_name = "Windows.Trojan.Guloader"
        reference_sample = "6ae7089aa6beaa09b1c3aa3ecf28a884d8ca84f780aab39902223721493b1f99"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $djb2_str_compare = { 83 C0 08 83 3C 04 00 0F 84 [4] 39 14 04 75 }
        $check_exception = { 8B 45 ?? 8B 00 38 EC 8B 58 ?? 84 FD 81 38 05 00 00 C0 }
        $parse_mem = { 18 00 10 00 00 83 C0 18 50 83 E8 04 81 00 00 10 00 00 50 }
        $hw_bp = { 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [7] 39 48 18 }
        $scan_protection = { 39 ?? 14 8B [5] 0F 84 }
    condition:
        2 of them
}

