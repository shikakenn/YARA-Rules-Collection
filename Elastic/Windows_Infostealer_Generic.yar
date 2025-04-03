rule Windows_Infostealer_Generic_acde9261 {
    meta:
        id = "7BrjktXtLC6DRWl8YYjbtx"
        fingerprint = "v1_sha256_86897117295bdcf79fad9f2ad939fabe89e3770309122ba142c7a26c926148c5"
        version = "1.0"
        date = "2024-10-21"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Observed in Stealc/Vidar samples"
        category = "INFO"
        threat_name = "Windows.Infostealer.Generic"
        reference_sample = "b46239c47a835757bba49078728f693b7273b0e3755e2968deac4aa92e90364d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "ChromeFuckNewCookies" ascii fullword
        $str2 = "/c timeout /t 10 & del /f /q \"" ascii fullword
        $str3 = "56574883EC2889D74889CEE8AAAAFFFF85FF74084889F1E8AAAAAAAA4889F04883C4285F5EC3CCCCCCCCCCCCCCCCCCCC56574883ECAA"
        $seq1 = { 81 FA 6B 03 EE 4C 74 ?? 81 FA 77 03 EE 4C 74 ?? 81 FA 80 68 55 FB 74 ?? 81 FA 92 68 55 FB }
    condition:
        2 of them
}

