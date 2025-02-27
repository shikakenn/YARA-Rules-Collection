rule Windows_VulnDriver_ATSZIO_e22cc429 {
    meta:
        id = "ivTgZogd3e2TxNagJfSYq"
        fingerprint = "v1_sha256_e3f057d5a5c47a1f3b4d50e2ad0ebb3a4ffe0efe513a0d375f827fadb3328d80"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Name: ATSZIO.sys"
        category = "INFO"
        threat_name = "Windows.VulnDriver.ATSZIO"
        reference_sample = "01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

