rule BuerLoader
{
    meta:
        id = "3REt3BesmdcafdlpxlNMmI"
        fingerprint = "v1_sha256_05c1f008f0a2bb8232867977fb23a5ae8312f10f0637c6265561052596319c29"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly & Rony (@r0ny_123)"
        description = "NA"
        category = "INFO"
        cape_type = "BuerLoader Payload"

    strings:
        $trap = {0F 31 89 45 ?? 6A 00 8D 45 ?? 8B CB 50 E8 [4] 0F 31}
        $decode = {8A 0E 84 C9 74 0E 8B D0 2A 0F 46 88 0A 42 8A 0E 84 C9 75 F4 5F 5E 5D C2 04 00}
        $op = {33 C0 85 D2 7E 1? 3B C7 7D [0-15] 40 3B C2 7C ?? EB 02}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
