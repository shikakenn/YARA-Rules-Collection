rule Lumma
{
    meta:
        id = "6txjIgJF8hvsvZMPNTNcMF"
        fingerprint = "v1_sha256_44408ffa7870dbc1a8a31567dd743f46542da01ed8083e5413392920b9d1bafe"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Lumma Payload"
        category = "INFO"
        cape_type = "Lumma Payload"
        packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
        packed = "23ff1c20b16d9afaf1ce443784fc9a025434a010e2194de9dec041788c369887"

    strings:
        $decode1 = {C1 (E9|EA) 02 [0-3] 0F B6 (44|4C) ?? FF 83 (F8|F9) 3D 74 05 83 (F8|F9) 2E 75 01 (49|4A) [0-30] 2E 75}
        $decode2 = {B0 40 C3 B0 3F C3 89 C8 04 D0 3C 09 77 06 80 C1 04 89 C8 C3 89 C8 04 BF 3C}
        $decode3 = {B0 40 C3 B0 3F C3 80 F9 30 72 ?? 80 F9 39 77 06 80 C1 04 89 C8 C3}
    condition:
        uint16(0) == 0x5a4d and any of them
}
