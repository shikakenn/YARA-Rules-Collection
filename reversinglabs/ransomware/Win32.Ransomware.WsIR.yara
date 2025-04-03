rule Win32_Ransomware_WsIR : tc_detection malicious
{
    meta:
        id = "4QcEMJSQwLD8827iUlKwGq"
        fingerprint = "v1_sha256_c22c01f93945c7721ebfe5e7a09c3bf2b9d0ad95740bc0a76b4e61741f61d82c"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects WsIR ransomware."
        category = "MALWARE"
        malware = "WSIR"
        tc_detection_type = "Ransomware"
        tc_detection_name = "WsIR"
        tc_detection_factor = 5

    strings:

        $find_files = {
            6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53
            55 8B E9 8D 4C 24 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B 4C 24 ?? C7 84 24 ?? ?? ?? ?? ??
            ?? ?? ?? 8B 41 ?? 85 C0 74 ?? 8D 54 24 ?? 6A ?? 52 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B 00
            68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4C 24 ?? 85 C0 0F 95 C3 E8 ?? ?? ?? ??
            84 DB 74 ?? 68 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4C 24 ?? E8
            ?? ?? ?? ?? 8B 4C 24 ?? 8D 44 24 ?? 50 51 FF 15 ?? ?? ?? ?? 83 F8 ?? 89 44 24 ?? 75
            ?? 8D 4C 24 ?? 89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 56 8B B4 24 ?? ??
            ?? ?? 57 8B 3D ?? ?? ?? ?? BB ?? ?? ?? ?? F6 44 24 ?? ?? 74 ?? 8D 54 24 ?? 68 ?? ??
            ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8D 44 24 ?? 68 ?? ?? ?? ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 85 C0 74 ?? 8B 45 ?? 8D 54 24 ?? 52 6A ?? 8D 8C 24 ?? ?? ?? ?? 68 ??
            ?? ?? ?? 50 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ??
            ?? ?? ?? ?? 89 4C 24 ?? 89 5C 24 ?? FF D7 8B 54 24 ?? 8D 4C 24 ?? 51 52 FF 15 ?? ??
            ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 56 6A ?? 68
            ?? ?? ?? ?? 51 FF D7 8D 4C 24 ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F
            5E 8B 8C 24 ?? ?? ?? ?? 5D 5B 64 89 0D ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? C2
        }

        $encrypt_files = {
            FF 75 ?? 8B 5D ?? FF 33 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 68 ?? ?? ??
            ?? FF 75 ?? 8B 5D ?? FF 33 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 68 ?? ??
            ?? ?? 6A ?? 8B 45 ?? 85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 85
            C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B
            5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ??
            83 C4 ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 6A ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4
            ?? 89 45 ?? 8B 45 ?? 50 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 58 89 45 ??
            E9
        }

        $exec_proc = {
            52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 1D ?? ??
            ?? ?? 8D 44 24 ?? 68 ?? ?? ?? ?? 50 FF D3 8D 4C 24 ?? 8D 54 24 ?? 51 52 68 ?? ?? ??
            ?? 8B CF E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 44 24 ?? 68 ?? ?? ?? ?? 50 E8 ??
            ?? ?? ?? 8B F0 83 C4 ?? 85 F6 75 ?? 8D 4C 24 ?? 68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B
            F0 83 C4 ?? 85 F6 75 ?? 8D 54 24 ?? 52 FF 15 ?? ?? ?? ?? 8D 74 04 ?? EB ?? 8D 57 ??
            8D 4C 24 ?? 52 E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 48 ?? 85 C9 0F 85 ?? ?? ?? ?? 8D 4C 24
            ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 EB ?? C6 06 ?? 68 ?? ?? ??
            ?? 56 FF D3 8B 44 24 ?? 50 56 FF D3 8D 4C 24 ?? 55 51 FF 15 ?? ?? ?? ?? 8B F0 33 D2
            83 FE ?? 0F 9F C2 8D 4C 24 ?? 8B F2 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ??
            5D 8B C6 5B 8B 8C 24 ?? ?? ?? ?? 5F 5E 64 89 0D ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? C2
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            $encrypt_files
        ) and
        (
            $exec_proc
        )
}
