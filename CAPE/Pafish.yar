rule Pafish
{
    meta:
        id = "6BiWvHUTNBNHxBGyzF4D5S"
        fingerprint = "v1_sha256_0a51bb2817e9fa5e599d0554de854ef62b128bcf5a22a69c33d56e16270f1c74"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Paranoid Fish Sandbox Detection"
        category = "INFO"
        cape_type = "Pafish Payload"

    strings:
        $rdtsc_vmexit = {8B 45 E8 80 F4 00 89 C3 8B 45 EC 80 F4 00 89 C6 89 F0 09 D8 85 C0 75 07}
        $cape_string = "cape_options"
    condition:
        uint16(0) == 0x5A4D and $rdtsc_vmexit and not $cape_string
}
