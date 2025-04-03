rule Windows_Hacktool_ChromeKatz_fa232bba {
    meta:
        id = "4L2t6KVoHkkAzOYiZwPLP5"
        fingerprint = "v1_sha256_c86291fadd51845cbd7428b159e401d78ac77090e14e34d06bf7bf2018f4502a"
        version = "1.0"
        date = "2024-03-27"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.ChromeKatz"
        reference_sample = "3f6922049422df14f1a1777001fea54b18fbfb0a4b03c4ee27786bfbc3b8ab87"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "CookieKatz.exe"
        $s2 = "Targeting Chrome"
        $s3 = "Targeting Msedgewebview2"
        $s4 = "Failed to find the first pattern"
        $s5 = "WalkCookieMap"
        $s6 = "Found CookieMonster on 0x%p"
        $s7 = "Cookie Key:"
        $s8 = "Failed to read cookie value" wide
        $s9 = "Failed to read cookie struct" wide
        $s10 = "Error reading left node"
    condition:
        5 of them
}

