rule Win32_Ransomware_NanoLocker : tc_detection malicious
{
    meta:
        id = "7n3DlZcmJ320NRGsGSBqNS"
        fingerprint = "v1_sha256_7fdb021f22d97bf8a00fd856ef913695a0d6fbaad1138b5a5cc2cc8768b130be"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects NanoLocker ransomware."
        category = "MALWARE"
        malware = "NANOLOCKER"
        tc_detection_type = "Ransomware"
        tc_detection_name = "NanoLocker"
        tc_detection_factor = 5

    strings:

        $encrypt_file_1 = {
            68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? FF 35 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 05 ?? ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 
            05 ?? ?? ?? ?? ?? 8D 3D ?? ?? ?? ?? 33 C9 C6 07 ?? 47 41 81 F9 ?? ?? ?? ?? 75 ?? C7 
            05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 0F 84 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 
            ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 
            ?? 6A ?? 6A ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? 
            ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 0F 84 ?? ?? ?? ?? 81 3D 
            ?? ?? ?? ?? ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 81 C6 ?? ?? ?? ?? 56 E8 
            ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 03 F0 46 8A 06 3C ?? 0F 85 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8
        }

        $encrypt_file_2 = {
            A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? 81 3D ?? ?? ?? ?? 
            ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A ?? 
            E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? 
            ?? ?? ?? 2D ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? 
            ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            6A ?? 6A ?? 6A ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? FF 35 ?? 
            ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? 
            ?? ?? FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? FF 35 ?? 
            ?? ?? ?? E8
        }

        $remote_server_1 = {
            E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? 
            ?? ?? 83 F8 ?? 72 ?? C6 05 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 
            35 ?? ?? ?? ?? E8
        }

        $remote_server_2 = {
            E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 35 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? A3 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 35 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8
        }

        $enum_shares_and_encrypt_files = {
            E8 ?? ?? ?? ?? C1 C8 ?? BA ?? ?? ?? ?? 23 D0 60 83 FA ?? 75 ?? 68 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 83 F8 ?? 76 ?? 83 F8 ?? 74 ?? 8D 35 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 56 68 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 61 8A 06 46 0A C0 75 ?? 8A 06 0A C0 75 ?? 61 D1 C8 8A 1D ?? 
            ?? ?? ?? FE C3 88 1D ?? ?? ?? ?? 80 FB ?? 76 ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? FF 35 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 
            FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8
        }

    condition:
        uint16(0) == 0x5A4D and $encrypt_file_1 and $encrypt_file_2 and $remote_server_1 and $remote_server_2 and $enum_shares_and_encrypt_files
}
