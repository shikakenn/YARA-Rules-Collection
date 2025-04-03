rule Windows_VulnDriver_Fileseclab_4a21229a {
    meta:
        id = "5ZtowVGavXqGFx8kkbJQ29"
        fingerprint = "v1_sha256_bac78186f3d46c6765bacaf6a324ff94e449261cefe2594cb38c4cc25db1f0de"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Fileseclab"
        reference_sample = "ae55a0e93e5ef3948adecf20fa55b0f555dcf40589917a5bfbaa732075f0cc12"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "filwfp.sys"
        $a2 = "filnk.sys"
        $a3 = { 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 5C 00 66 00 69 00 6C 00 77 00 66 00 70 00 }
        $a4 = { 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 5C 00 66 00 69 00 6C 00 77 00 66 00 70 00 }
        $b1 = { 31 00 2C 00 20 00 30 00 2C 00 20 00 30 00 2C 00 20 00 }
        $b2 = { 32 00 2C 00 20 00 30 00 2C 00 20 00 30 00 2C 00 20 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and 1 of ($a*) and 1 of ($b*)
}

