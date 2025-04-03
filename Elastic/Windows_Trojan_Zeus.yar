rule Windows_Trojan_Zeus_e51c60d7 {
    meta:
        id = "48g8Z0ihfgUhZXbgcJfNPf"
        fingerprint = "v1_sha256_cde738f95dbad1fbad59e20528b2f577e5e3ee5fcb37c68a45d53c689d2af525"
        version = "1.0"
        date = "2021-02-07"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects strings used in Zeus web injects. Many other malware families are built on Zeus and may hit on this signature."
        category = "INFO"
        reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
        threat_name = "Windows.Trojan.Zeus"
        reference_sample = "d7e9cb60674e0a05ad17eb96f8796d9f23844a33f83aba5e207b81979d0f2bf3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "name=%s&port=%u" ascii fullword
        $a2 = "data_inject" ascii wide fullword
        $a3 = "keylog.txt" ascii fullword
        $a4 = "User-agent: %s]]]" ascii fullword
        $a5 = "%s\\%02d.bmp" ascii fullword
    condition:
        all of them
}

