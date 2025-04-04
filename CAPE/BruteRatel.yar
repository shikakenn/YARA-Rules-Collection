rule BruteRatel
{
    meta:
        id = "2A12ghJHtoDfIsVOY4kLpp"
        fingerprint = "v1_sha256_0984977c716d6f8e068c045166eb5db77c9fbce27513e555dceca348375f1a66"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "BruteRatel Payload"
        category = "INFO"
        cape_type = "BruteRatel Payload"

    strings:
        $syscall1 = {49 89 CA 4? 89 ?? (41 FF|FF)}
        $syscall2 = {49 89 CA 48 8B 44 24 ?? FF 64 24}
        $jmpapi = {49 89 ?? 10 49 C7 45 08 ?? 00 00 00 E8 00 00 00 00 ?? (48|49) 83 [2] 41 FF E2}
        $decode = {89 C2 8A 14 17 40 38 EA 75 06 FF C0 89 03 EB 0B 41 88 14 08 48 FF C1 FF 03 EB}
    condition:
        2 of them
}
