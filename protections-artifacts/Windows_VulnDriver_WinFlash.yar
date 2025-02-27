rule Windows_VulnDriver_WinFlash_881758da {
    meta:
        id = "1JFYmD6z1KVeKbXKrbBT4m"
        fingerprint = "v1_sha256_a46ac1f19ba5d9543c88434575870b61fbb935cd4c4e28cb80a077502af7d2db"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.WinFlash"
        reference_sample = "8596ea3952d84eeef8f5dc5b0b83014feb101ec295b2d80910f21508a95aa026"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\WinFlash64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

