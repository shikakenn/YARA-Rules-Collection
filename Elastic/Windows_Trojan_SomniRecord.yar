rule Windows_Trojan_SomniRecord_097e66bd {
    meta:
        id = "2fviLgTNdr7ycUxYjW8RmE"
        fingerprint = "v1_sha256_a75436c8152bc6eae6023fc69ea681ae5ffdd33c1f0398e119bd98fd6bc06573"
        version = "1.0"
        date = "2023-03-01"
        modified = "2023-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/not-sleeping-anymore-somnirecords-wakeup-call"
        threat_name = "Windows.Trojan.SomniRecord"
        reference_sample = "54114c23f499738a06fd8b8ab2a8458c03ac8cc81e706702fcd1c64a075e4dcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 66 81 38 4E 52 75 06 80 78 02 3A 74 34 48 FF C0 4C 8D 47 FE 4C 2B C0 48 8B C8 BA 4E 00 00 00 }
        $str0 = "%s-%s-%s.%s" ascii fullword
        $str1 = "ECM-" ascii fullword
        $str2 = "RESP:" ascii fullword
        $str3 = "PROBE" ascii fullword
        $str4 = "SYS" ascii fullword
        $str5 = "PSL" ascii fullword
        $str6 = "WS-" ascii fullword
        $str7 = "There were no commands" ascii fullword
        $str8 = "String abc = Request.Form" ascii fullword
    condition:
        $a or all of ($str*)
}

