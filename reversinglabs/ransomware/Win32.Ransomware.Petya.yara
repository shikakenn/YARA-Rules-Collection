import "pe"

rule Win32_Ransomware_Petya : tc_detection malicious
{
    
    meta:
        id = "CN5AC9mZUGD95PvVTlxzy"
        fingerprint = "v1_sha256_d2adafcb21b627d614eab79e64e2b96ad09fae796d0670452a19490d8781ce99"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Petya ransomware."
        category = "MALWARE"
        malware = "PETYA"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Petya"
        tc_detection_factor = 5

    strings:
        $entry_point = {
            55 8B EC 56 8B 75 ?? 57 83 FE ?? 75 ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 56 FF 75 ?? E8 ?? ?? ?? ?? 8B F8 85 F6 75 ?? E8 ?? 
            ?? ?? ?? 8B C7 5F 5E 5D C2 
        }

        $shutdown_pattern = {
            55 8B EC 83 EC ?? 8D 45 ?? 56 50 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 
            75 ?? 33 C0 EB ?? 8D 45 ?? 33 F6 50 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 56 56 56 8D 
            45 ?? C7 45 ?? ?? ?? ?? ?? 50 56 FF 75 ?? C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 
            15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 50 FF 15 
            ?? ?? ?? ?? 8D 4D ?? 51 6A ?? 56 56 56 68 ?? ?? ?? ?? FF D0 33 C0 83 C4 ?? 40 5E 8B 
            E5 5D C3 
        }

        $sectionxxxx_pattern = {
            83 EC ?? 53 55 8B C2 89 4C 24 ?? 56 57 8B C8 89 44 24 ?? 33 D2 E8 ?? ?? ?? ?? 85 C0 
            74 ?? 0F B7 48 ?? 8B FA 83 C1 ?? 03 C8 0F B7 40 ?? 89 44 24 ?? 85 C0 74 ?? BE ?? ?? 
            ?? ?? 2B F1 80 39 ?? 8D 59 ?? 6A ?? 5D 75 ?? 85 ED 74 ?? 0F BE 2C 1E 0F BE 03 43 3B 
            E8 74 ?? 83 C1 ?? 83 EE ?? 47 3B 7C 24 ?? 72 ?? 8B CA 85 C9 74 ?? 8B 51 ?? 8B 5C 24 
            ?? 8B FB 03 54 24 ?? 8B F2 8B 4A ?? A5 83 C1 ?? 03 CA 89 4B ?? A5 A5 8B 43 ?? 8D 72 
            ?? 89 43 ?? 8B 43 ?? 89 43 ?? B8 ?? ?? ?? ?? 89 73 ?? 66 39 01 74 ?? 8B 7A ?? 8B 2A 
            03 7A ?? 74 ?? 33 DB 43 2B DE 33 D2 8D 0C 33 8B C5 F7 F1 30 16 46 4F 75 ?? B2 ?? 5F 
            5E 5D 0F B6 C2 5B 83 C4 ?? C3 
        }

        $crypt_gen_pattern = {
            55 8B EC 53 57 8B 7D ?? 8D 45 ?? 68 ?? ?? ?? ?? 6A ?? 33 DB 53 53 50 89 1F FF 15 ?? 
            ?? ?? ?? 85 C0 75 ?? 6A ?? 58 EB ?? 56 FF 75 ?? 8B 75 ?? 56 FF 75 ?? FF 15 ?? ?? ?? 
            ?? 85 C0 75 ?? 6A ?? 58 EB ?? 53 FF 75 ?? FF 15 ?? ?? ?? ?? 89 37 33 C0 5E 5F 5B 5D 
            C3 
        }

    condition:
        uint16(0) == 0x5A4D and ($entry_point at pe.entry_point) and $shutdown_pattern and $sectionxxxx_pattern and $crypt_gen_pattern
            
}
