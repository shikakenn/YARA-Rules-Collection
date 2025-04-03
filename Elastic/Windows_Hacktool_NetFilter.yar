rule Windows_Hacktool_NetFilter_e8243dae {
    meta:
        id = "3BXSCgu2Am33p0jzOIc6Go"
        fingerprint = "v1_sha256_c551bd87e73f980d8836b13449490de5e639d768b72d9006d90969f3140b28e2"
        version = "1.0"
        date = "2022-04-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "760be95d4c04b10df89a78414facf91c0961020e80561eee6e2cb94b43b76510"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "[NetFlt]:CTRL NDIS ModifyARP"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_NetFilter_dd576d28 {
    meta:
        id = "3Z40C8Cbk7GvLnOuRyg34T"
        fingerprint = "v1_sha256_7635ed94ca77c7705df4d2a9c5546ece86bf831b5bf5355943419174e0387b86"
        version = "1.0"
        date = "2022-04-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "88cfe6d7c81d0064045c4198d6ec7d3c50dc3ec8e36e053456ed1b50fc8c23bf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\NetProxyDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_NetFilter_b4f2a520 {
    meta:
        id = "3LPvp45Rs3V1TcGYTYU1pp"
        fingerprint = "v1_sha256_520d2194593f1622a3b905fe182a0773447a4eee3472e7701cce977f5bf4fbae"
        version = "1.0"
        date = "2022-04-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "5d0d5373c5e52c4405f4bd963413e6ef3490b7c4c919ec2d4e3fb92e91f397a0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\netfilterdrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_NetFilter_1cae6e26 {
    meta:
        id = "6LYN2Clax9l8UQYk7E4Drw"
        fingerprint = "v1_sha256_29c0edc03934e6e7275c3870a8808e03ec85dacb1f54e10efca3123d2257db98"
        version = "1.0"
        date = "2022-04-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "e2ec3b2a93c473d88bfdf2deb1969d15ab61737acc1ee8e08234bc5513ee87ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\Driver_Map.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

