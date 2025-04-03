rule Windows_Trojan_NapListener_e8f16920 {
    meta:
        id = "5uIPcfZZMWNRrRatVvUw4N"
        fingerprint = "v1_sha256_6cb7b5051fab2b56f39b2805788b5b0838a095b41fcc623fe412b215736be5d4"
        version = "1.0"
        date = "2023-02-28"
        modified = "2023-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.NapListener"
        reference_sample = "6e8c5bb2dfc90bca380c6f42af7458c8b8af40b7be95fab91e7c67b0dee664c4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $start_routine = { 02 28 08 00 00 0A 00 00 28 03 00 00 0A 0A 14 FE 06 04 00 00 06 73 04 00 00 0A 73 05 00 00 0A 0B 16 28 06 00 00 0A 00 07 06 6F 07 00 00 0A 00 00 2A }
        $main_routine = { 6F 22 00 00 0A 13 0E 11 0D 1F 24 14 16 8D 16 00 00 01 14 6F 23 00 00 0A 13 0F 11 0F 14 6F 24 00 00 0A 13 10 11 0E 11 10 18 8D 01 00 00 01 }
        $start_thread = { 00 28 03 00 00 0A 0A 14 FE 06 04 00 00 06 73 04 00 00 0A 73 05 00 00 0A 0B 16 28 06 00 00 0A 00 07 06 6F 07 00 00 0A 00 2A }
    condition:
        2 of them
}

rule Windows_Trojan_NapListener_414180a7 {
    meta:
        id = "1jCTrK9GsE9KVDkIuwozTK"
        fingerprint = "v1_sha256_52d3ddebdc1a8aa4bcb902273bd2d3b4f9b51f248d25e7ae1cc260a9550111f5"
        version = "1.0"
        date = "2023-02-28"
        modified = "2023-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.NapListener"
        reference_sample = "6e8c5bb2dfc90bca380c6f42af7458c8b8af40b7be95fab91e7c67b0dee664c4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "https://*:443/ews/MsExgHealthCheckd/" ascii wide
        $a2 = "FillFromEncodedBytes" ascii wide
        $a3 = "Exception caught" ascii wide
        $a4 = "text/html; charset=utf-8" ascii wide
        $a5 = ".Run" ascii wide
        $a6 = "sdafwe3rwe23" ascii wide
    condition:
        5 of them
}

