rule Windows_Hacktool_Gmer_8aabdd5e {
    meta:
        id = "m7lhJ71VmHbUwK83dOxIx"
        fingerprint = "v1_sha256_acdab89a7703a743927cec60fbc84af2fd469403bee6f211c865fb96e9c92498"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Gmer"
        reference_sample = "18c909a2b8c5e16821d6ef908f56881aa0ecceeaccb5fa1e54995935fcfd12f7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\gmer64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

