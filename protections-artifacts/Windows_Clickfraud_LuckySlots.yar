rule Windows_Clickfraud_LuckySlots_a82433b6 {
    meta:
        id = "2nP23K54xamZ6efCoNkhES"
        fingerprint = "v1_sha256_342dafb67ae8557de66ac810482e2747ae88c76f07c244f1a465351fcc72cab9"
        version = "1.0"
        date = "2024-08-21"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Clickfraud.LuckySlots"
        reference_sample = "6503770b34c53025793f1674af87d80a8f6ed44b5780490796012a2b771b8f84"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "lwxatisme" ascii fullword
        $a2 = "/{flag}/" ascii fullword
        $a3 = "\"KEYWORDS\"" ascii fullword
        $a4 = "WebKitFormBoundaryBHNkQBGxcQrf7zY1" ascii fullword
        $a5 = "baidu|sogou|360|yisou|bing|google|coccoc|byte" ascii fullword
        $a6 = "Video|xoso|dabong|nohu|bet|app|games|ios|Casino" ascii fullword
        $a7 = "baidu.com|so.com|sogou.com|sm.cn|bing.com|google|coccoc|toutiao" ascii fullword
    condition:
        all of them
}

