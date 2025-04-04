rule Windows_Trojan_Blackwood_2b94bce9 {
    meta:
        id = "2Z9Sxl2NV1jEmPdqGPJkwB"
        fingerprint = "v1_sha256_279e85ce3bb974ce5af541e7307cb2fd1031f36c9da013756883172a765b0e19"
        version = "1.0"
        date = "2024-03-22"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Blackwood"
        reference_sample = "c37dd77f659059da7e12e13b063036ee69097a4d2f88c170832fff78f3788991"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5F 8C FB 62 69 00 65 00 78 00 70 00 6C 00 6F 00 72 00 65 00 2E 00 65 00 78 00 65 00 }
        $a2 = { C6 44 24 0C 6D C6 44 24 0D 73 C6 44 24 0E 68 C6 44 24 10 70 C6 44 24 11 2E C6 44 24 12 64 }
        $a3 = { 6D 79 6E 73 70 2E 64 6C 6C 00 4E 53 50 43 6C 65 61 6E 75 70 00 4E 53 50 53 74 61 72 74 75 70 }
        $b1 = "index.dat"
        $b2 = "Mozilla/4.0 (compatible;MSIE 5.0; Windows 98)"
        $b3 = "http://www.baidu.com/id=%s&ad=%d&os=%d.%d&t=%d"
        $b4 = "SetEntriesInAcl Error %u"
        $b5 = "AllocateAndInitializeSid Error %u"
    condition:
        1 of ($a*) or all of ($b*)
}

