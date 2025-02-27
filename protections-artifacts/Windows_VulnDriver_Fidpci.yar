rule Windows_VulnDriver_Fidpci_cb7f69b5 {
    meta:
        id = "7b5ne9QoPCMak78nXviphm"
        fingerprint = "v1_sha256_459429fb4e5156890f19c451e48676c9cd06eaab1c2eaea9236737c795086b5f"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Fidpci"
        reference_sample = "3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\fidpcidrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

