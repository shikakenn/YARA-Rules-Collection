rule Zloader
{
    meta:
        id = "2K1fxEycPDSPG2D0MhM6AH"
        fingerprint = "v1_sha256_a94efd87c69146cf5771341974e5abe789445d67dde3e045e1b87d3131539ff9"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly, enzok"
        description = "Zloader Payload"
        category = "INFO"
        hash = "adbd0c7096a7373be82dd03df1aae61cb39e0a155c00bbb9c67abc01d48718aa"
        cape_type = "Zloader Payload"

    strings:
        $rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
        $decrypt_conf = {83 C4 04 84 C0 74 5? E8 [4] E8 [4] E8 [4] E8 [4] ?8 [4] ?8 [4] ?8}
        $decrypt_conf_1 = {48 8d [5] [0-6] e8 [4] 48 [3-4] 48 [3-4] 48 [6] E8}
        $decrypt_conf_2 = {48 8d [5] 4? [5] e8 [4] 48 [3-4] 48 8d [5] E8 [4] 48}
        $decrypt_key_1 = {66 89 C2 4? 8D 0D [3] 00 4? B? FC 03 00 00 E8 [4] 4? 83 C4 [1-2] C3}
        $decrypt_key_2 = {48 8d 0d [3] 00 66 89 ?? 4? 89 F0 4? [2-5] E8 [4-5] 4? 83 C4}
        $decrypt_key_3 = {48 8d 0d [3] 00 e8 [4] 66 89 [3] b? [4] e8 [4] 66 8b}
    condition:
        uint16(0) == 0x5A4D and 1 of ($decrypt_conf*) and (1 of ($decrypt_key*) or $rc4_init)
}
