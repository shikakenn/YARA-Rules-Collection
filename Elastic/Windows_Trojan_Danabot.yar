rule Windows_Trojan_Danabot_6f3dadb2 {
    meta:
        id = "303MtqJ3PhS8fbVEB1wJdp"
        fingerprint = "v1_sha256_b9c895be9eab775726abd2c13256d598c5b79bceb2d652c30b1df4cfc37e4b93"
        version = "1.0"
        date = "2021-08-15"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Danabot"
        reference_sample = "716e5a3d29ff525aed30c18061daff4b496f3f828ba2ac763efd857062a42e96"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%s.dll" ascii fullword
        $a2 = "del_ini://Main|Password|" wide fullword
        $a3 = "S-Password.txt" wide fullword
        $a4 = "BiosTime:" wide fullword
        $a5 = "%lu:%s:%s:%d:%s" ascii fullword
        $a6 = "DNS:%s" ascii fullword
        $a7 = "THttpInject&" ascii fullword
        $a8 = "TCookies&" ascii fullword
    condition:
        all of them
}

