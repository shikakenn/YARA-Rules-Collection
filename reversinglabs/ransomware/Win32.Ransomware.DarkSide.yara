rule Win32_Ransomware_DarkSide : tc_detection malicious
{
    meta:
        id = "4D42w2crmcET3b91zm1uNo"
        fingerprint = "v1_sha256_128af9a1b143e4b0928dd2b243e69497be906175f44815cc5703f17cce48ec9d"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects DarkSide ransomware."
        category = "MALWARE"
        malware = "DARKSIDE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "DarkSide"
        tc_detection_factor = 5

    strings:

        $find_files_v1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 51 52 56 57 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??
            83 7D ?? ?? 0F 84 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 04 45 ?? ?? ??
            ?? 50 6A ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ??
            ?? FF 75 ?? FF 75 ?? FF 15 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? E8 ?? ?? ?? ?? C7 45 ?? ??
            ?? ?? ?? 8D 45 ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? 6A ?? 8D 85 ??
            ?? ?? ?? 50 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 8D 9D ?? ??
            ?? ?? 83 3B ?? 74 ?? 81 3B ?? ?? ?? ?? 74 ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8D 85 ?? ??
            ?? ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 75 ?? FF 15 ?? ?? ?? ?? 83 7D ??
            ?? 74 ?? FF 75 ?? 6A ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 45 ?? 5F 5E 5A 59 5B
            8B E5 5D C2
        }

        $enumerate_drives = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 51 52 56 57 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF 15
            ?? ?? ?? ?? 8B D8 85 DB 74 ?? C1 EB ?? 8D B5 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 F8
            ?? 74 ?? 83 F8 ?? 75 ?? 56 E8 ?? ?? ?? ?? 8D 76 ?? 4B 85 DB 75 ?? 5F 5E 5A 59 5B 8B
            E5 5D C3 55 8B EC 81 EC ?? ?? ?? ?? 53 51 52 56 57 8D 85 ?? ?? ?? ?? 50 FF 75 ?? E8
            ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 45 ?? C7
            00 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4
            ?? 6A ?? 6A ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ??
            ?? 89 45 ?? 83 7D ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 66 A9 ?? ?? 74 ?? 6A ?? 8D 85 ?? ??
            ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 51 8D 40 ?? 50 FF 15 ?? ?? ??
            ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 15
            ?? ?? ?? ?? 85 C0 75 ?? FF 75 ?? FF 15 ?? ?? ?? ?? 5F 5E 5A 59 5B 8B E5 5D C2
        }

        $escalate_privileges  = {
            55 8B EC 83 C4 ?? 53 51 52 56 57 8D 45 ?? 50 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 85 C0 0F
            85 ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 8D 45 ?? 50 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? FF 75
            ?? 6A ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 8D 45 ?? 50
            FF 75 ?? FF 75 ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 75 ?? AD 8B F8 83
            7E ?? ?? 74 ?? C7 46 ?? ?? ?? ?? ?? 83 C6 ?? 4F 85 FF 75 ?? 6A ?? 6A ?? 6A ?? FF 75
            ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? FF 75 ?? 6A ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ??
            ?? FF 75 ?? FF 15 ?? ?? ?? ?? 5F 5E 5A 59 5B 8B E5 5D C3
        }

        $enumerate_netshare = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 51 52 56 57 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF 15
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 7D ?? 8D 45 ?? 50 8D 45 ?? 50 8D 45 ?? 50 6A ??
            8D 45 ?? 50 6A ?? 57 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 75 ?? 83 7E ?? ?? 75 ?? 68 ??
            ?? ?? ?? 6A ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 C7 03 ?? ?? ?? ?? C7 43 ??
            ?? ?? ?? ?? C7 43 ?? ?? ?? ?? ?? C7 43 ?? ?? ?? ?? ?? 8D 47 ?? 50 53 FF 15 ?? ?? ??
            ?? 83 C4 ?? 53 FF 15 ?? ?? ?? ?? FF 36 53 FF 15 ?? ?? ?? ?? 83 C4 ?? 53 E8 ?? ?? ??
            ?? 53 6A ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 C6 ?? FF 4D ?? 83 7D ?? ?? 75 ??
            FF 15 ?? ?? ?? ?? 5F 5E 5A 59 5B 8B E5 5D C2
        }

        $find_files_v2 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 51 52 56 57 8D 85 ?? ?? ?? ?? 50 FF 75 ?? E8 ?? ?? ??
            ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D BD
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 83 C4 ?? 57 FF 15 ?? ?? ?? ??
            83 C4 ?? 66 83 7C 47 ?? ?? 74 ?? 66 C7 04 47 ?? ?? 83 C7 ?? C7 04 47 ?? ?? ?? ?? C7
            44 47 ?? ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 8D 85 ?? ?? ?? ??
            50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 66 A9 ?? ?? 74 ??
            8D 9D ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 83 C4
            ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 83 C4 ?? 83 C0 ?? 53 50 FF 15 ?? ?? ?? ?? 83 C4 ?? 56
            E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 75 ??
            FF 15 ?? ?? ?? ?? 5F 5E 5A 59 5B 8B E5 5D C2
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            (
                $find_files_v1 and
                $enumerate_drives and
                $escalate_privileges
            ) or
            (
                $find_files_v2 and
                $enumerate_netshare
            )
        )
}
