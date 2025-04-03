rule Windows_VulnDriver_RentDrv_b6711b6b {
    meta:
        id = "5vMenKv6H4ssloPDcvUgjA"
        fingerprint = "v1_sha256_3b3d66fefb4f0efbc8b86687925eac25284a6efad3acc74ad4a627d975cd5e7b"
        version = "1.0"
        date = "2024-08-19"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.RentDrv"
        reference_sample = "9165d4f3036919a96b86d24b64d75d692802c7513f2b3054b20be40c212240a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "rentdrv_x64.pdb"
        $str2 = "KillProcess"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and all of them
}

