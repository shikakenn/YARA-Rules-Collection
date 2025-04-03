rule Windows_Hacktool_ProcessHacker_3d01069e {
    meta:
        id = "2vqSSiW9XI3j5m9Wv8VqLM"
        fingerprint = "v1_sha256_bcba74aa20b62329c48060bfebaf49ab12f89f9ec3a09fc0c0cb702de5e2b940"
        version = "1.0"
        date = "2022-03-30"
        modified = "2022-03-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.ProcessHacker"
        reference_sample = "70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = "OriginalFilename\x00kprocesshacker.sys" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

