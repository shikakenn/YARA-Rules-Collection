rule Windows_VulnDriver_AsIo_5f9f29be {
    meta:
        id = "4OVoSp8MMwNavB8GNyaC4H"
        fingerprint = "v1_sha256_a901d81737c7e6d00e87f0eec758dd063eade59d9883e85e04a33bb18f2f99de"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.AsIo"
        reference_sample = "52a90fd1546c068b92add52c29fbb8a87d472a57e609146bbcb34862f9dcec15"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\AsIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

