rule Windows_Trojan_DCRat_1aeea1ac {
    meta:
        id = "3cNk780EIkHy9qhTyB8Ufs"
        fingerprint = "v1_sha256_6163e04a40ed52d5e94662131511c3ae08d473719c364e0f7de60dff7fa92cf7"
        version = "1.0"
        date = "2022-01-15"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DCRat"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "havecamera" ascii fullword
        $a2 = "timeout 3 > NUL" wide fullword
        $a3 = "START \"\" \"" wide fullword
        $a4 = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" wide fullword
        $a5 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" wide fullword
        $b1 = "DcRatByqwqdanchun" ascii fullword
        $b2 = "DcRat By qwqdanchun1" ascii fullword
    condition:
        5 of ($a*) or 1 of ($b*)
}

