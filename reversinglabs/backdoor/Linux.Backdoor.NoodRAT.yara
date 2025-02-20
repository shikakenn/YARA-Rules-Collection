rule Linux_Backdoor_NoodRAT : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "NOODRAT"
        description         = "Yara rule that detects NoodRAT backdoor."

        tc_detection_type   = "Backdoor"
        tc_detection_name   = "NoodRAT"
        tc_detection_factor = 5

    strings:

        $change_name_on_system_p1 = {
            41 56 41 55 41 54 55 53 48 81 EC ?? ?? ?? ?? 48 89 FB 48 8D BC 24 ?? ?? ?? ?? B8 ??
            ?? ?? ?? B9 ?? ?? ?? ?? F3 48 AB 48 8D BC 24 ?? ?? ?? ?? B1 ?? F3 48 AB C6 84 24 ??
            ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ??
            C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ??
            ?? ?? ?? ?? 80 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ?? 0F B7 15
            ?? ?? ?? ?? 66 89 55 ?? 4C 8D 65 ?? 0F B7 D2 BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ??
            48 8D 94 24 ?? ?? ?? ?? 0F B7 75 ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ??
            4C 89 E6 48 89 EF E8 ?? ?? ?? ?? 4C 8B 03 48 C7 C6 ?? ?? ?? ?? 4C 89 C7 B8 ?? ?? ??
            ?? 48 89 F1 F2 AE 48 F7 D1 48 8D 14 31 48 89 EF 48 89 F1 F2 AE 48 89 CE 48 F7 D6 48
            83 EE ?? 48 39 F2 72 ?? BE ?? ?? ?? ?? 4C 89 C7 E8 ?? ?? ?? ?? 48 89 EE 48 8B 3B E8
            ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? B8 ?? ?? ?? ?? B9
            ?? ?? ?? ?? F3 48 AB 48 8D BC 24 ?? ?? ?? ?? B1 ?? F3 48 AB C6 84 24 ?? ?? ?? ?? ??
            C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ??
            ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ??
            C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ??
            ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ??
            C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ??
            ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? 48 8D B4 24 ?? ?? ?? ??
            48 8D BC 24 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C2 B8 ?? ?? ?? ?? 48 85
            D2 0F 8E ?? ?? ?? ?? 48 C7 C2 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? 48 89 D1 F2 AE 48
        }

        $change_name_on_system_p2 = {
            89 CB 48 8D BC 24 ?? ?? ?? ?? 48 89 D1 F2 AE F7 D3 8D 5C 0B ?? 85 DB B8 ?? ?? ?? ??
            0F 4E D8 48 8D B4 24 ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48
            89 EF B8 ?? ?? ?? ?? 48 C7 C1 ?? ?? ?? ?? F2 AE 48 F7 D1 48 8D 79 ?? 48 63 D3 48 63
            FF 48 8D 7C 3D ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ??
            ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ??
            C6 84 24 ?? ?? ?? ?? ?? 48 8D B4 24 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 49 89 C6 48
            8D B4 24 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C3 48 89 E7 B9 ??
            ?? ?? ?? B8 ?? ?? ?? ?? F3 48 AB C6 07 ?? 48 89 E5 41 BC ?? ?? ?? ?? 41 BD ?? ?? ??
            ?? EB ?? 48 89 EF 4C 89 E9 4C 89 E0 F3 48 AB C6 07 ?? 48 89 D9 BA ?? ?? ?? ?? BE ??
            ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 85 C0 7E ?? 48 63 D0 4C 89 F1 BE ?? ?? ?? ?? 48 89
            E7 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89
            F7 E8 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ??
            ?? 85 C0 75 ?? 48 8D BC 24 ?? ?? ?? ?? 48 89 BC 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ??
            ?? ?? ?? ?? ?? 48 8D B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? EB ?? 85 C0 7E
            ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ??
            ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5B 5D 41 5C 41 5D 41 5E C3
        }

        $decrypt_configuration_p1 = {
            41 57 41 56 41 55 41 54 55 53 48 81 EC ?? ?? ?? ?? 48 89 7C 24 ?? 48 8D 9C 24 ?? ??
            ?? ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 DF F3 48 AB C6 07 ?? 48 8D 54 24 ?? B1 ??
            48 89 D7 F3 48 AB C6 44 24 ?? ?? C6 44 24 ?? ?? C6 44 24 ?? ?? C6 44 24 ?? ?? C6 44
            24 ?? ?? C6 44 24 ?? ?? C6 44 24 ?? ?? C6 44 24 ?? ?? 48 8D 54 24 ?? 0F B7 35 ?? ??
            ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 C7 C1 ?? ?? ??
            ?? F2 AE 48 F7 D1 48 83 E9 ?? 48 81 F9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 46 D1 BE ??
            ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? C6 44 24 ?? ?? C6 44 24 ?? ?? 48 8D 74 24 ?? 48 89
            DF E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 50 ?? 48 89 54 24 ?? C6 00 ?? 48
            8D 74 24 ?? 48 89 D7 E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 48 ?? 48 89 4C
            24 ?? C6 00 ?? 48 8D 74 24 ?? 48 89 CF E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 85 C0 0F 84
            ?? ?? ?? ?? C6 00 ?? 48 8D B4 24 ?? ?? ?? ?? 48 C7 C5 ?? ?? ?? ?? 48 89 F7 41 BC ??
            ?? ?? ?? 48 89 E9 44 89 E0 F2 AE 48 F7 D1 48 01 E9 48 8D 5C 24 ?? 48 81 F9 ?? ?? ??
            ?? BA ?? ?? ?? ?? 48 0F 46 D1 48 89 DF E8 ?? ?? ?? ?? 48 89 DF 48 89 E9 44 89 E0 F2
            AE 48 89 CD 48 F7 D5 83 ED ?? 8D 45 ?? 48 98 80 7C 04 ?? ?? 74 ?? 48 63 C5 C6 44 04
            ?? ?? 83 C5 ?? 48 63 ED C6 44 2C ?? ?? 4C 8D 6C 24 ?? 4C 89 EB BD ?? ?? ?? ?? C7 44
            24 ?? ?? ?? ?? ?? 66 C7 44 24 ?? ?? ?? 41 BC ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7
            44 24 ?? ?? ?? ?? ?? 49 C7 C6 ?? ?? ?? ?? 4D 89 EF E9 ?? ?? ?? ?? 0F B6 03 3C ?? 75
            ?? 44 8B 64 24 ?? 4D 6B E4 ?? 4C 03 64 24 ?? 49 8D 7C 24 ?? 83 7C 24 ?? ?? BA ?? ??
            ?? ?? 0F 4E 54 24 ?? 48 63 D2 8B 74 24 ?? 48 8D 44 24 ?? 48 8D 34 30 E8
        }

        $decrypt_configuration_p2 = {
            0F B7 54 24 ?? 66 41 89 54 24 ?? 83 44 24 ?? ?? 83 7C 24 ?? ?? 77 ?? 89 6C 24 ?? 41
            BC ?? ?? ?? ?? EB ?? 3C ?? 75 ?? 48 8D 7B ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ??
            ?? ?? 66 89 44 24 ?? 44 89 64 24 ?? EB ?? 41 83 C4 ?? 83 C5 ?? 48 83 C3 ?? 4C 89 F1
            4C 89 FF B8 ?? ?? ?? ?? F2 AE 48 F7 D1 48 83 E9 ?? 48 89 D8 4C 29 E8 48 39 C8 0F 82
            ?? ?? ?? ?? 8B 4C 24 ?? 48 8B 54 24 ?? 89 8A ?? ?? ?? ?? 48 8D 5C 24 ?? B9 ?? ?? ??
            ?? B8 ?? ?? ?? ?? 48 89 DF F3 48 AB 48 8B 7C 24 ?? 48 C7 C1 ?? ?? ?? ?? F2 AE 48 F7
            D1 48 8D 51 ?? 48 8B 74 24 ?? 48 89 DF E8 ?? ?? ?? ?? 80 7C 24 ?? ?? 75 ?? 48 8B 44
            24 ?? C6 80 ?? ?? ?? ?? ?? 80 7C 24 ?? ?? 75 ?? 48 8B 54 24 ?? C6 82 ?? ?? ?? ?? ??
            80 7C 24 ?? ?? 75 ?? 48 8B 4C 24 ?? C6 81 ?? ?? ?? ?? ?? 80 7C 24 ?? ?? 75 ?? 48 8B
            44 24 ?? C6 80 ?? ?? ?? ?? ?? 80 7C 24 ?? ?? 75 ?? 48 8B 54 24 ?? C6 82 ?? ?? ?? ??
            ?? 80 7C 24 ?? ?? 75 ?? 48 8B 4C 24 ?? C6 81 ?? ?? ?? ?? ?? 80 7C 24 ?? ?? 75 ?? 48
            8B 44 24 ?? C6 80 ?? ?? ?? ?? ?? 48 8D 5C 24 ?? B9 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 89
            DF F3 48 AB 48 8B 7C 24 ?? 48 C7 C1 ?? ?? ?? ?? F2 AE 48 F7 D1 48 83 E9 ?? 48 81 F9
            ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 46 D1 48 8B 74 24 ?? 48 89 DF E8 ?? ?? ?? ?? C6 44
            24 ?? ?? C6 44 24 ?? ?? 48 8D 74 24 ?? 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ??
            ?? ?? 48 8D 7C 24 ?? B8 ?? ?? ?? ?? 48 C7 C1 ?? ?? ?? ?? F2 AE 48 F7 D1 83 E9 ?? 8D
        }

        $decrypt_configuration_p3 = {
            41 ?? 48 98 80 7C 04 ?? ?? 74 ?? 48 63 C1 C6 44 04 ?? ?? 83 C1 ?? 48 63 C9 C6 44 0C
            ?? ?? 4C 89 EB BD ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 49 C7
            C4 ?? ?? ?? ?? 4C 8D 74 24 ?? 41 BF ?? ?? ?? ?? EB ?? 0F B6 03 3C ?? 75 ?? 8B 7C 24
            ?? 48 8D 54 24 ?? 48 8D 3C 3A BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 54 24
            ?? 48 81 C2 ?? ?? ?? ?? 48 8B 4C 24 ?? 66 89 44 91 ?? 0F B7 44 24 ?? 66 89 44 91 ??
            83 44 24 ?? ?? 83 7C 24 ?? ?? 77 ?? 89 6C 24 ?? EB ?? 3C ?? 75 ?? 48 8D 7B ?? BA ??
            ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 89 44 24 ?? 83 C5 ?? 48 83 C3 ?? 4C 89 E1
            4C 89 F7 44 89 F8 F2 AE 48 F7 D1 48 83 E9 ?? 48 89 D8 4C 29 E8 48 39 C8 0F 82 ?? ??
            ?? ?? 8B 4C 24 ?? 48 8B 54 24 ?? 89 8A ?? ?? ?? ?? EB ?? 48 8B 44 24 ?? C7 80 ?? ??
            ?? ?? ?? ?? ?? ?? 48 8B 7C 24 ?? 48 83 C7 ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ??
            ?? ?? 85 C0 BA ?? ?? ?? ?? 0F 4E C2 48 8B 54 24 ?? 89 82 ?? ?? ?? ?? B8 ?? ?? ?? ??
            EB ?? B8 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5B 5D 41 5C 41 5D 41 5E 41 5F C3
        }

        $encrypt_and_send_data = {
            48 89 5C 24 ?? 48 89 6C 24 ?? 4C 89 64 24 ?? 4C 89 6C 24 ?? 4C 89 74 24 ?? 4C 89 7C
            24 ?? 48 83 EC ?? 41 89 FC 48 89 F5 49 89 D6 41 89 CD 48 85 F6 0F 84 ?? ?? ?? ?? BF
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C3 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 89 03
            0F B6 45 ?? 88 43 ?? 8B 6B ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 ?? E8 ?? ?? ?? ?? BA ??
            ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 44 89 E9 BA ?? ?? ?? ?? 48 89 DE 44
            89 E7 E8 ?? ?? ?? ?? 85 C0 75 ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 ?? E8 ?? ?? ?? ?? 48
            89 DF E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 85 ED 74
            ?? 4D 85 F6 75 ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9
            ?? ?? ?? ?? 4C 63 FD 4C 89 FF E8 ?? ?? ?? ?? 48 89 C3 48 85 C0 74 ?? 4C 89 FA 4C 89
            F6 48 89 C7 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 89 EE 48 89 DF E8 ?? ?? ?? ?? 44 89 E9 89
            EA 48 89 DE 44 89 E7 E8 ?? ?? ?? ?? 85 C0 75 ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 ?? E8
            ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? EB ?? 48 8B 3D ?? ?? ?? ?? 48 83
            C7 ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? EB ?? B8 ?? ?? ?? ?? 48
            8B 5C 24 ?? 48 8B 6C 24 ?? 4C 8B 64 24 ?? 4C 8B 6C 24 ?? 4C 8B 74 24 ?? 4C 8B 7C 24
            ?? 48 83 C4 ?? C3
        }

        $receive_and_decrypt_data = {
            48 89 5C 24 ?? 48 89 6C 24 ?? 4C 89 64 24 ?? 4C 89 6C 24 ?? 48 83 EC ?? 41 89 FC 48
            89 F3 49 89 D5 89 CD 48 85 F6 74 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? BA ??
            ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 8B 53 ?? 85 D2 74 ?? 4D 85 ED 75 ??
            B8 ?? ?? ?? ?? EB ?? 81 FA ?? ?? ?? ?? 77 ?? 89 E9 4C 89 EE 44 89 E7 E8 ?? ?? ?? ??
            85 C0 74 ?? 8B 73 ?? BA ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? EB ?? B8
            ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B 6C 24 ?? 4C 8B 64 24 ?? 4C 8B 6C 24 ?? 48 83 C4 ??
            C3
        }

    condition:
        uint32(0) == 0x464C457F and
        (
            (
                all of ($change_name_on_system_p*)
            ) and
            (
                all of ($decrypt_configuration_p*)
            ) and
            (
                $encrypt_and_send_data
            ) and
            (
                $receive_and_decrypt_data
            )
        )
}