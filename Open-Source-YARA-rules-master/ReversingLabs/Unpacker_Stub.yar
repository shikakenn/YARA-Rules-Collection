rule Unpacker_Stub
{
    meta:
        id = "5oyKoUmPE2PXTLKFt8h9p6"
        fingerprint = "v1_sha256_2e1055aaa8c50d51eff2726c71bb9745ead46fd8167395dc47c0a779dd61d2c1"
        version = "1.0"
        date = "2020-12-30"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Malware Utkonos"
        description = "First Byte in decoded unpacker stub"
        category = "INFO"
        reference = "https://blog.reversinglabs.com/blog/code-reuse-across-packers-and-dll-loaders"
        exemplar = "c1d31fa7484170247564e89c97cc325d1f317fb8c8efe50e4d126c7881adf499"

strings:
$a = {E8 00 00 00 00 5B 81 EB [4] 8D 83 [4] 89 83 [4] 8D B3 [4] 89 B3 [4] 8B 46 ?? 89 83 [4] 8D B3 [4] 56 8D B3 [4] 56 6A ?? 68 [4] 8D BB [4] FF D7}
condition:
(uint16(0) == 0x5A4D and uint32 (uint32(0x3C)) == 0x00004550) and $a
}
