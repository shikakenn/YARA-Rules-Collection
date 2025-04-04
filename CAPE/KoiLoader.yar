rule KoiLoader
{
    meta:
        id = "6U2Ybjxqa31AUsRGg5fKjy"
        fingerprint = "v1_sha256_264a536632f8f11c904b00c9d2e505b3263c733ad8fbc2ef19c25a5ad58cef90"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "YungBinary"
        description = "KoiLoader"
        category = "INFO"
        hash = "b462e3235c7578450b2b56a8aff875a3d99d22f6970a01db3ba98f7ecb6b01a0"
        cape_type = "KoiLoader Payload"

    strings:
        $chunk_1 = {
            68 27 11 68 05
            8B 45 ??
            50
            E8 ?? ?? ?? ??
            83 C4 08
            89 45 ??
            68 15 B1 B3 09
            8B 4D ??
            51
            E8 ?? ?? ?? ??
            83 C4 08
            89 45 ??
            68 B5 96 AA 0D
            8B 55 ??
            52
            E8 ?? ?? ?? ??
            83 C4 08
            89 45 ??
            6A 00
            FF 15 ?? ?? ?? ??
        }

    condition:
        $chunk_1

}
