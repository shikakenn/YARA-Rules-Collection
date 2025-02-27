rule Windows_Trojan_DBatLoader_f93a8e90 {
    meta:
        id = "2ZzhhURHrfWFpohxZ5cNas"
        fingerprint = "v1_sha256_6fe91d91bb383c66a6dc623b02817411a39b88030142517f4048c5c25fbb4ac5"
        version = "1.0"
        date = "2022-03-11"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DBatLoader"
        reference_sample = "f72d7e445702bbf6b762ebb19d521452b9c76953d93b4d691e0e3e508790256e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { FF 00 74 17 8B 45 E8 0F B6 7C 18 FF 66 03 7D EC 66 0F AF 7D F4 66 03 }
    condition:
        all of them
}

