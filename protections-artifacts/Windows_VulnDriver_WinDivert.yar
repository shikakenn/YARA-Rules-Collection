rule Windows_VulnDriver_WinDivert_25991186 {
    meta:
        id = "2nN0F5xc0Ee2x8CwfK5kDJ"
        fingerprint = "v1_sha256_a67679bb2f23d1f6691c9ad23da1fd4c2402701ba1929c7abf078d7d95011a08"
        version = "1.0"
        date = "2024-06-20"
        modified = "2024-07-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.WinDivert"
        reference_sample = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 44 00 69 00 76 00 65 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name
}

