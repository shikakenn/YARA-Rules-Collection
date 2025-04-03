rule Windows_Trojan_Backoff_22798f00 {
    meta:
        id = "3DcLcY6JymbGmqNIBIm9H8"
        fingerprint = "v1_sha256_65b5aff18a4e0bc29d7cc4cfbe2d5882f99a855727fe467b2ba2e2851c43d21b"
        version = "1.0"
        date = "2022-08-10"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Backoff"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\nsskrnl" fullword
        $str2 = "Upload KeyLogs" fullword
        $str3 = "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s" fullword
        $str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
        $str5 = "\\OracleJava\\Log.txt" fullword
        $str6 = "[Ctrl+%c]" fullword
    condition:
        3 of them
}

