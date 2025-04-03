rule Windows_VulnDriver_Zam_928812a7 {
    meta:
        id = "1wDSinYyAwoTB5WxJHh3x4"
        fingerprint = "v1_sha256_82ca874d60d8a0ee04aca39f59415f22797e7e0337314c88dd8ebad1a823d200"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $pdb_64 = "AntiMalware\\bin\\zam64.pdb"
        $pdb_32 = "AntiMalware\\bin\\zam32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and any of ($pdb_*)
}

rule Windows_VulnDriver_Zam_7c86d260 {
    meta:
        id = "1AEvvWu9ozN8GpM7EfVpVp"
        fingerprint = "v1_sha256_cc29f26c222825eb5262d91065a00243bc913fe2071d8ad6b0dc61dd22798f1e"
        version = "1.0"
        date = "2024-07-16"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "6f55c148bb27c14408cf0f16f344abcd63539174ac855e510a42d78cfaec451c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 5A 00 41 00 4D 00 2E 00 65 00 78 00 65 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
        $s1 = "Advanced Malware Protection" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $s1
}

