rule Windows_VulnDriver_GlckIo_39c4abd4 {
    meta:
        id = "2u9meHfNE5xOLPN6EgiLow"
        fingerprint = "v1_sha256_fd43503c9427a386674c06bb790e110ac23c27d8fc4adedbaa8a9b7cb0cbafd4"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-08-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.GlckIo"
        reference_sample = "3a5ec83fe670e5e23aef3afa0a7241053f5b6be5e6ca01766d6b5f9177183c25"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\GLCKIO2.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1
}

rule Windows_VulnDriver_GlckIo_68d5afbb {
    meta:
        id = "3RcEb6P9utCNdTOFZU3Muv"
        fingerprint = "v1_sha256_0b5f0d408a5c4089ef496c5f8241a34d0468cc3d21e89e41dc105a0df0855d38"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.GlckIo"
        reference_sample = "5ae23f1fcf3fb735fcf1fa27f27e610d9945d668a149c7b7b0c84ffd6409d99a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "[GLKIO2] Cannot resolve ZwQueryInformationProcess"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1
}

