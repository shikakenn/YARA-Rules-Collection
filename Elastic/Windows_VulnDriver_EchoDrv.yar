rule Windows_VulnDriver_EchoDrv_d17ff31c {
    meta:
        id = "5A7EHQA11Ofs2zZSxArta7"
        fingerprint = "v1_sha256_0b2eb3c5da8703749ee63662495d6e8738ccdc353f3ac3df48e25a77312c0da0"
        version = "1.0"
        date = "2023-10-31"
        modified = "2023-11-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.EchoDrv"
        reference_sample = "ea3c5569405ed02ec24298534a983bcb5de113c18bc3fd01a4dd0b5839cd17b9"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "D:\\WACATACC\\Projects\\Programs\\Echo\\x64\\Release\\echo-driver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1
}

