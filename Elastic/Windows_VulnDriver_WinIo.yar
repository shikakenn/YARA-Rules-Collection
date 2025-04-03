rule Windows_VulnDriver_WinIo_c9cc6d00 {
    meta:
        id = "3LRXrg1eeyvFH0wn7MIU5Y"
        fingerprint = "v1_sha256_4b6a78c2c807cf1f569ae9bc275d42d9c895efba7a2d64fec0652e3cb163d553"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\WinioSys.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_WinIo_b0f21a70 {
    meta:
        id = "6wDKXYitTFBJ4VAVmrGNqf"
        fingerprint = "v1_sha256_c82d95e805898f9a9a1ffccb483e506df0a53dc420068314e7c724e4947f3572"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "IOCTL_WINIO_WRITEMSR"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

