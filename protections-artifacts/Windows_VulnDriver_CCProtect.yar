rule Windows_VulnDriver_CCProtect_0d3ee86f {
    meta:
        id = "3Sm4tWnMQzIa99gt0M2T08"
        fingerprint = "v1_sha256_4da5cf6b5cd00f8f7ba6daf8e8b4c6161cf9e0166dea39943b32a54f35dfd6c2"
        version = "1.0"
        date = "2024-09-09"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.CCProtect"
        reference_sample = "5f0cfe8357bb52b45068ddbac053e32bc38e6cb5e086746f5402657b0a5cfb1c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $pdb = "\\CcProtect.pdb"
        $original_filename = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 }
        $file_version = { 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 31 00 2E 00 ( 30 | 31 | 32 | 33 ) 00 3? 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and all of them
}

