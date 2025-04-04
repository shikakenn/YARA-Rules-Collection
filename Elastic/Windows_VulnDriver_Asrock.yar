rule Windows_VulnDriver_Asrock_986d2d3c {
    meta:
        id = "7CSOKPPpH0EA2HKkxqKky8"
        fingerprint = "v1_sha256_d767a1ecdff557753f80ac9d73f02364dd035f7a287d0f260316f807364af2d5"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\AsrDrv106.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_Asrock_cdf192f9 {
    meta:
        id = "4WfXuZDdkjyRfqZEdaPjgX"
        fingerprint = "v1_sha256_2f844b6d3fa19fd39097395175162578ad71d78c61dad104efd320cd8285fa6b"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\AsrDrv103.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_Asrock_0eca57dc {
    meta:
        id = "56rmdAxKqqb31PiBerxwwx"
        fingerprint = "v1_sha256_82a0cba571dc58ed8d3fd87d3650ec0c1016e6c8e972547f6120ba91c8febce1"
        version = "1.0"
        date = "2023-07-20"
        modified = "2023-07-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: AsrSetupDrv103.sys, Version: 1.00.00.0000 built by: WinDDK"
        category = "INFO"
        threat_name = "Windows.Vulndriver.Asrock"
        reference_sample = "9d9346e6f46f831e263385a9bd32428e01919cca26a035bbb8e9cb00bf410bc3"
        reference_sample = "a0728184caead84f2e88777d833765f2d8af6a20aad77b426e07e76ef91f5c3f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 [1-8] 41 00 73 00 72 00 53 00 65 00 74 00 75 00 70 00 44 00 72 00 76 00 31 00 30 00 33 00 2E 00 73 00 79 00 73 }
        $file_version = { 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E [1-8] 31 00 2E 00 30 00 30 00 2E 00 30 00 30 00 2E 00 30 00 30 00 30 00 30 00 20 00 62 00 75 00 69 00 6C 00 74 00 20 00 62 00 79 00 3A 00 20 00 57 00 69 00 6E 00 44 00 44 00 4B }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $file_version
}

