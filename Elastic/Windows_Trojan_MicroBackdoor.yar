rule Windows_Trojan_MicroBackdoor_903e33c3 {
    meta:
        id = "4S9IrOD44K1cQhHbaww0w5"
        fingerprint = "v1_sha256_5f96f68df442eb1da21d87c3ae954c4e36cf87db583cbef1775f8ca9e76b776e"
        version = "1.0"
        date = "2022-03-07"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.MicroBackdoor"
        reference_sample = "fbbfcc81a976b57739ef13c1545ea4409a1c69720469c05ba249a42d532f9c21"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 83 EC 1C 56 57 E8 33 01 00 00 8B F8 85 FF 74 48 BA 26 80 AC C8 8B CF E8 E1 01 00 00 BA }
    condition:
        all of them
}

rule Windows_Trojan_MicroBackdoor_46f2e5fd {
    meta:
        id = "34pmKBo443nEzWkMsoYspv"
        fingerprint = "v1_sha256_580be4c5b058916c2bc67a7964522a7c369bb254394e3cedbf0da025105231c4"
        version = "1.0"
        date = "2022-03-07"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.MicroBackdoor"
        reference_sample = "fbbfcc81a976b57739ef13c1545ea4409a1c69720469c05ba249a42d532f9c21"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "cmd.exe /C \"%s%s\"" wide fullword
        $a2 = "%s|%s|%d|%s|%d|%d" wide fullword
        $a3 = "{{{$%.8x}}}" ascii fullword
        $a4 = "30D78F9B-C56E-472C-8A29-E9F27FD8C985" ascii fullword
        $a5 = "chcp 65001 > NUL & " wide fullword
        $a6 = "CONNECT %s:%d HTTP/1.0" ascii fullword
    condition:
        5 of them
}

