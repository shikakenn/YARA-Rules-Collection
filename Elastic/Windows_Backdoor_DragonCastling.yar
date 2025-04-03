rule Windows_Backdoor_DragonCastling_4ecf6f9f {
    meta:
        id = "6fcdPCzTTX74c0Hpy5vlTS"
        fingerprint = "v1_sha256_26ff86354230f1006bd451eab5c1634b91888330d124a06dd2dfa5ab515d6e1a"
        version = "1.0"
        date = "2022-11-08"
        modified = "2022-12-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Backdoor.DragonCastling"
        reference_sample = "9776c7ae6ca73f87d7c838257a5bcd946372fbb77ebed42eebdfb633b13cd387"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "recv bomb" ascii fullword
        $a2 = "%s\\kbg%x.dat"
        $a3 = "\\smcache.dat" wide fullword
        $a4 = "%s\\game_%x.log"
        $a5 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
        $a7 = "HOST: %ws:%ws" ascii fullword
        $a8 = "; Windows NT %d.%d" wide fullword
        $a9 = "Mozilla / 5.0 (Windows NT 6.3; WOW64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 41.0.2272.118 Safari / 537.36" ascii fullword
        $a10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" wide fullword
    condition:
        5 of them
}

