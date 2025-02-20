rule Win32_Ransomware_Jormungand : tc_detection malicious
{
    meta:
        id = "6YF89LdyyHqNN6NfnbgHsC"
        fingerprint = "v1_sha256_049eb4533b37d8d72e50dd1e803a897758386643770d47b3e7690f58e44d5236"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Jormungand ransomware."
        category = "MALWARE"
        malware = "JORMUNGAND"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Jormungand"
        tc_detection_factor = 5

    strings:

        $drop_ransom_note = {
            64 8B 0D ?? ?? ?? ?? 8B 89 ?? ?? ?? ?? 8D 44 24 ?? 3B 41 ?? 0F 86 ?? ?? ?? ?? 81 EC
            ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 89 04 24 8B 84 24 ?? ?? ?? ?? 89 44 24 ?? 8B 84 24 ??
            ?? ?? ?? 89 44 24 ?? 8B 84 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89
            84 24 ?? ?? ?? ?? 8B 4C 24 ?? 89 4C 24 ?? 8D 54 24 ?? 89 14 24 8B 94 24 ?? ?? ?? ??
            89 54 24 ?? 8B 94 24 ?? ?? ?? ?? 89 54 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ??
            8B 54 24 ?? 8B 9C 24 ?? ?? ?? ?? 89 1C 24 8B 9C 24 ?? ?? ?? ?? 89 5C 24 ?? 89 44 24
            ?? 89 4C 24 ?? 89 54 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 84 24 ?? ?? ?? ?? 8B 4C 24
            ?? 89 4C 24 ?? 8B 54 24 ?? 89 54 24 ?? C7 04 24 ?? ?? ?? ?? 8B 9C 24 ?? ?? ?? ?? 89
            5C 24 ?? 8B 9C 24 ?? ?? ?? ?? 89 5C 24 ?? 8D 1D ?? ?? ?? ?? 89 5C 24 ?? C7 44 24 ??
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 89 04 24 89 4C 24 ?? C7 44 24 ??
            ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 84 24 ?? ?? ?? ??
            8D 4C 24 ?? 89 0C 24 8B 8C 24 ?? ?? ?? ?? 89 4C 24 ?? 8B 4C 24 ?? 89 4C 24 ?? 8B 4C
            24 ?? 89 4C 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 89 44 24 ?? 89 4C 24 ?? 8D
            44 24 ?? 89 04 24 8B 84 24 ?? ?? ?? ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? E8 ?? ??
            ?? ?? 8B 44 24 ?? 8B 4C 24 ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? 89 4C 24 ?? E8 ?? ??
            ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 8B 54 24 ?? 8B 9C 24 ?? ?? ?? ?? 89 1C 24 89 44 24 ??
            89 4C 24 ?? 89 54 24 ?? E8 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ??
            81 C4 ?? ?? ?? ?? C3 E8
        }

        $encrypt_files_aes = {
            64 8B 0D ?? ?? ?? ?? 8B 89 ?? ?? ?? ?? 3B 61 ?? 0F 86 ?? ?? ?? ?? 83 EC ?? 8B 44 24
            ?? 89 04 24 8B 44 24 ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24
            ?? 8B 4C 24 ?? 8B 54 24 ?? 8B 5C 24 ?? 85 D2 74 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24
            ?? ?? ?? ?? ?? 89 54 24 ?? 89 5C 24 ?? 83 C4 ?? C3 89 44 24 ?? 89 4C 24 ?? 8B 50 ??
            89 0C 24 FF D2 8B 44 24 ?? 8B 4C 24 ?? 89 0C 24 8B 4C 24 ?? 89 4C 24 ?? 8B 4C 24 ??
            89 4C 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 8B 4C 24 ?? 89 4C 24
            ?? 8B 54 24 ?? 89 54 24 ?? C7 04 24 ?? ?? ?? ?? 8D 1D ?? ?? ?? ?? 89 5C 24 ?? C7 44
            24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 8B 54 24 ?? 8B 5C 24 ?? 89
            1C 24 8B 5C 24 ?? 89 5C 24 ?? 89 44 24 ?? 89 4C 24 ?? 89 54 24 ?? E8 ?? ?? ?? ?? 8B
            44 24 ?? 89 44 24 ?? 8B 4C 24 ?? 89 4C 24 ?? 8D 15 ?? ?? ?? ?? 89 14 24 8B 54 24 ??
            89 54 24 ?? 89 54 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 8B 4C 24 ?? 89 4C 24
            ?? 8B 54 24 ?? 89 54 24 ?? 8B 5C 24 ?? 8B 5B ?? 89 44 24 ?? 89 4C 24 ?? 89 54 24 ??
            8B 6C 24 ?? 89 6C 24 ?? 8B 6C 24 ?? 89 6C 24 ?? 8B 6C 24 ?? 89 6C 24 ?? 8B 6C 24 ??
            89 2C 24 FF D3 8B 05 ?? ?? ?? ?? 89 04 24 8B 44 24 ?? 89 44 24 ?? 8B 44 24 ?? 89 44
            24 ?? 8B 44 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 89 44 24 ?? 89
            4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 83 C4 ?? C3 E8
        }

        $encrypt_files_rsa = {
            64 8B 0D ?? ?? ?? ?? 8B 89 ?? ?? ?? ?? 3B 61 ?? 0F 86 ?? ?? ?? ?? 83 EC ?? C7 04 24
            ?? ?? ?? ?? 8D 05 ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B
            44 24 ?? 8B 4C 24 ?? 8B 54 24 ?? 89 14 24 89 4C 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B
            44 24 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 48 ?? 8B 50 ?? 8B 40 ?? 89 0C 24 89 54 24 ?? 89
            44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 8B 54 24 ?? 8B 5C 24 ?? 85 D2 75 ??
            8D 15 ?? ?? ?? ?? 39 D0 0F 85 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 89 04
            24 89 54 24 ?? 89 4C 24 ?? 8B 44 24 ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? 8B 44 24
            ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 8B 54 24 ?? 8B 5C 24 ?? 8B 6C
            24 ?? 89 44 24 ?? 89 4C 24 ?? 89 54 24 ?? 89 5C 24 ?? 89 6C 24 ?? 83 C4 ?? C3 C7 44
            24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 54 24 ?? 89 5C
            24 ?? 83 C4 ?? C3 8D 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 44 24 ?? C7 40 ?? ??
            ?? ?? ?? 8B 0D ?? ?? ?? ?? 85 C9 75 ?? 8D 0D ?? ?? ?? ?? 89 08 C7 44 24 ?? ?? ?? ??
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 0D ?? ?? ?? ?? 89 4C 24 ?? 89
            44 24 ?? 83 C4 ?? C3 89 44 24 ?? 89 04 24 8D 0D ?? ?? ?? ?? 89 4C 24 ?? E8 ?? ?? ??
            ?? 8B 44 24 ?? EB ?? 89 04 24 89 54 24 ?? 8D 05 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ??
            ?? 0F 0B
        }

        $find_files = {
            64 8B 0D ?? ?? ?? ?? 8B 89 ?? ?? ?? ?? 3B 61 ?? 0F 86 ?? ?? ?? ?? 83 EC ?? C7 44 24
            ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 8D 05 ?? ??
            ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 44 24 ?? 89 04 24 8B 44 24 ?? 89 44
            24 ?? 8D 05 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 8B 0D ?? ?? ??
            ?? 8B 15 ?? ?? ?? ?? 89 44 24 ?? 89 4C 24 ?? 89 54 24 ?? 8B 05 ?? ?? ?? ?? 8B 0D ??
            ?? ?? ?? 8B 15 ?? ?? ?? ?? 89 44 24 ?? 89 4C 24 ?? 89 54 24 ?? 90 E8 ?? ?? ?? ?? 83
            C4 ?? C3 90 E8 ?? ?? ?? ?? 83 C4 ?? C3 E8
        }

        $remote_connection_p1 = {
            64 8B 0D ?? ?? ?? ?? 8B 89 ?? ?? ?? ?? 3B 61 ?? 0F 86 ?? ?? ?? ?? 83 EC ?? C7 04 24
            ?? ?? ?? ?? 8D 05 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D
            05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? C7 40 ?? ?? ?? ?? ??
            8D 0D ?? ?? ?? ?? 89 0C 24 E8 ?? ?? ?? ?? 8B 44 24 ?? C6 40 ?? ?? 8B 0D ?? ?? ?? ??
            8B 54 24 ?? 8D 5A ?? 85 C9 0F 85 ?? ?? ?? ?? 89 42 ?? 8D 05 ?? ?? ?? ?? 89 04 24 E8
            ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? C7 40 ?? ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 8D 0D
            ?? ?? ?? ?? 89 08 8B 0D ?? ?? ?? ?? 8D 50 ?? 85 C9 0F 85 ?? ?? ?? ?? 8B 4C 24 ?? 89
            48 ?? C7 04 24 ?? ?? ?? ?? 8D 05 ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8B
            44 24 ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? 8D 05 ?? ?? ?? ?? 89 44 24 ?? C7 44 24
            ?? ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44
            24 ?? 89 44 24 ?? 8B 4C 24 ?? 89 4C 24 ?? 8D 15 ?? ?? ?? ?? 89 14 24 E8 ?? ?? ?? ??
            8B 44 24 ?? 89 44 24 ?? 8B 4C 24 ?? 89 48 ?? 8B 0D ?? ?? ?? ?? 85 C9 0F 85 ?? ?? ??
            ?? 8B 4C 24 ?? 89 08 C7 40 ?? ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C7 40
        }

        $remote_connection_p2 = {
            C7 04 24 ?? ?? ?? ?? 8D 0D ?? ?? ?? ?? 89 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 4C 24
            ?? 89 4C 24 ?? 8B 4C 24 ?? 89 4C 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 89 4C
            24 ?? 89 44 24 ?? 8D 05 ?? ?? ?? ?? 89 04 24 C7 44 24 ?? ?? ?? ?? ?? 8D 05 ?? ?? ??
            ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 8B 4C
            24 ?? 8B 54 24 ?? 89 0C 24 89 54 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 04 24 8B 44 24
            ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 8B 4C 24 ?? 8B 54 24 ?? 89 0C
            24 89 54 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 75 ?? 90 E8 ?? ?? ?? ?? 83 C4 ?? C3
            8B 48 ?? 84 01 8B 40 ?? 89 44 24 ?? C7 04 24 ?? ?? ?? ?? 8D 41 ?? 89 44 24 ?? E8 ??
            ?? ?? ?? 85 C0 75 ?? EB ?? 90 E8 ?? ?? ?? ?? 83 C4 ?? C3 89 04 24 8B 4C 24 ?? 89 4C
            24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? E9 ?? ?? ?? ?? 89 14 24 8B 44 24 ?? 89 44 24 ?? E8
            ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 1C 24 89 44 24 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 90 E8
            ?? ?? ?? ?? 83 C4 ?? C3 E8
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_*)
        ) and
        (
            all of ($remote_connection_p*)
        ) and
        (
            $drop_ransom_note
        )
}
