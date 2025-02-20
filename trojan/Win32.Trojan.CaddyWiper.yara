rule Win32_Trojan_CaddyWiper : tc_detection malicious
{
    meta:
        id = "5jgoqi9DWr18WggcsP0HSp"
        fingerprint = "v1_sha256_178ff4171c09866f6b303bdff234beff1116d268995ee4dc236332e472d645b1"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects CaddyWiper trojan."
        category = "MALWARE"
        malware = "CADDYWIPER"
        mitre_att = "S0693"
        tc_detection_type = "Trojan"
        tc_detection_name = "CaddyWiper"
        tc_detection_factor = 5

    strings:

        $destroy_if_not_controller = {
            50 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 83 39 ?? 75 ?? EB ?? 8D 55 ?? 52 FF 55 ??
            C6 45 ?? 43 C6 45 ?? 3A C6 45 ?? 5C C6 45 ?? 55 C6 45 ?? 73 C6 45 ?? 65 C6 45 ?? 72
            C6 45 ?? 73 C6 45 ?? 00 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? C6 45 ?? ??
            C6 45 ?? ?? C6 45 ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 4D ?? 83 C1 ?? 89 4D ?? 83 7D
            ?? ?? 73 ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8A 45 ?? 04 ?? 88 45 ?? EB ?? E8 ??
            ?? ?? ?? 8B E5 5D C3
        }

        $erase_drive_data = {
            C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? 8D 4D ?? 89 8D ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ??
            6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 95 ?? ?? ?? ?? 89 45 ?? 83
            7D ?? ?? 74 ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ??
            ?? 51 68 ?? ?? ?? ?? 8B 55 ?? 52 FF 55 ?? 8B 45 ?? 50 FF 55 ?? 8A 4D ?? 88 4D ?? 8A
            55 ?? 80 EA ?? 88 55 ?? 8B 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 83 E9 ?? 89 8D ?? ?? ??
            ?? 85 C0 0F 85 ?? ?? ?? ?? 8B E5 5D C3
        }

        $erase_drives_recursively_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF C6 85 ?? ?? ?? ?? 2A C6 85 
            ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 5C C6 85 ?? ?? ?? ?? 00 8D 85 ?? ?? ?? ?? 50 8B 4D 
            ?? 51 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? 
            ?? ?? 51 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 
            C6 85 ?? ?? ?? ?? 46 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 64 
            C6 85 ?? ?? ?? ?? 46 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 73 
            C6 85 ?? ?? ?? ?? 74 C6 85 ?? ?? ?? ?? 46 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 6C 
            C6 85 ?? ?? ?? ?? 65 C6 85 ?? ?? ?? ?? 41 C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 6B 
            C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 65 C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 72 
            C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 65 
            C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 6C C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 33 
            C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 32 C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 2E 
            C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 6C 
            C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 6C C6 85 ?? ?? ?? ?? 00 C6 85 ?? ?? ?? ?? 00 
            C6 85 ?? ?? ?? ?? 00 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 E8
        }

        $erase_drives_recursively_2_p1 = {
            8D 45 ?? 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 89 85 ?? ?? ?? ?? 8D 95 ??
            ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ??
            ?? ?? 75 ?? E9 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 83 E1 ?? 0F 84 ?? ?? ?? ?? 0F BE 95 ??
            ?? ?? ?? 83 FA ?? 75 ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? 0F BE 8D ?? ?? ?? ?? 83 F9
            ?? 75 ?? E9 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 83 E2 ?? 75 ?? 8B 85 ?? ?? ?? ?? 83 E0 ??
            74 ?? E9 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 8D 85 ?? ?? ?? ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 E8 ??
            ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 95 ?? ?? ?? ?? 52
            E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 8D 95 ?? ??
            ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 8D 95 ??
            ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85
        }

        $erase_drives_recursively_2_p2 = {
            C0 75 ?? E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D
            ?? ?? ?? ?? 51 FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? E9 ??
            ?? ?? ?? 6A ?? 8B 95 ?? ?? ?? ?? 52 FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ??
            ?? ?? ?? 73 ?? E9 ?? ?? ?? ?? 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 76 ?? C7 85 ?? ?? ?? ??
            ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 6A ?? FF 95 ?? ?? ??
            ?? 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4
            ?? 6A ?? 6A ?? 6A ?? 8B 85 ?? ?? ?? ?? 50 FF 95 ?? ?? ?? ?? 6A ?? 8D 8D ?? ?? ?? ??
            51 8B 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 FF 95 ?? ?? ?? ??
            8B 95 ?? ?? ?? ?? 52 FF 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 55 ?? 8D 8D ?? ?? ??
            ?? 51 8B 95 ?? ?? ?? ?? 52 FF 95 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ??
            ?? 50 FF 95 ?? ?? ?? ?? 8B E5 5D C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $destroy_if_not_controller
        ) and
        (
            $erase_drive_data
        ) and
        (
            all of ($erase_drives_recursively_*)
        )
}
