rule Linux_Ransomware_KillDisk : tc_detection malicious
{
    meta:
        id = "5lgMZItHGR01Vvt7rIOkQt"
        fingerprint = "v1_sha256_3ed1fb2b7b24cd4d5100d93ed53a9ab28e1482bd0998a0538d8710a962ee839f"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects KillDisk ransomware."
        category = "MALWARE"
        malware = "KILLDISK"
        mitre_att = "S0607"
        tc_detection_type = "Ransomware"
        tc_detection_name = "KillDisk"
        tc_detection_factor = 5

    strings:

        $encrypt_files_1 = {
            55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 64 48 8B 04 25 ?? ?? ?? ?? 48 
            89 45 ?? 31 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85 
            ?? ?? ?? ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 85 C0 74 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 C7 
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 85 C0 79 ?? 48 8B 
            85 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 85 ?? ?? 
            ?? ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 78 ?? 48 8B 85 ?? ?? ?? ?? BE ?? 
            ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 
            85 C0 79 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 8D 90 ?? ?? ?? ?? 48 85 C0 
            48 0F 48 C2 48 C1 F8 ?? 48 89 85 ?? ?? ?? ?? 48 8B 45 ?? 48 85 C0 7E ?? 48 83 BD ?? 
            ?? ?? ?? ?? 7F ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 
            ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 8E ?? ?? ?? ?? 48 
            83 BD ?? ?? ?? ?? ?? 7F ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? 
            ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C2 48 C1
        }

        $encrypt_files_2 = {
            EA ?? 48 01 D0 48 D1 F8 48 C1 E0 ?? 48 89 C1 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 
            CE 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? 
            ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 8E ?? ?? ?? 
            ?? 48 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 BA ?? 
            ?? ?? ?? ?? ?? ?? ?? 48 89 C8 48 F7 EA 48 8D 04 0A 48 C1 F8 ?? 48 89 C2 48 89 C8 48 
            C1 F8 ?? 48 29 C2 48 89 D0 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? EB ?? 8B 
            85 ?? ?? ?? ?? C1 E0 ?? 48 63 C8 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 CE 89 C7 E8 
            ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 
            ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? 3B 85 ?? ?? ?? ?? 7C ?? 48 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 0F 8E ?? ?? ?? ?? 
            48 8B 8D ?? ?? ?? ?? 48 BA ?? ?? ?? ?? ?? ?? ?? ?? 48 89 C8 48 F7 EA 48 8D 04 0A 48 
            C1 F8 ?? 48 89 C2 48 89 C8 48 C1 F8 ?? 48 29 C2 48 89 D0 89 85 ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? EB ?? 8B 85 ?? ?? ?? ?? C1 E0 ?? 48 63 C8 8B 85 ?? ?? ?? ?? BA 
            ?? ?? ?? ?? 48 89 CE 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? 
            ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? EB ?? 83 85 ?? ?? ?? ?? ?? 83 85 ?? 
            ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 85 ?? ?? ?? ?? 7C ?? 8B 05 ?? ?? ?? ?? 89 C7 E8 ?? 
            ?? ?? ?? 8B 05 ?? ?? ?? ?? 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 8B 75 ?? 64 48 33 
            34 25 ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? C9 C3 
        }

        $search_files = {
            55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 64 48 8B 04 25 ?? ?? ?? ?? 48 
            89 45 ?? 31 C0 8B 05 ?? ?? ?? ?? 83 C0 ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 83 F8 
            ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 
            48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 85 ?? 
            ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 
            48 8B 85 ?? ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 ?? 
            E9 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 83 C0 
            ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            E9 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? 
            ?? 85 C0 74 ?? 48 8B 85 ?? ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? 
            ?? 85 C0 75 ?? 83 85 ?? ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 
            D6 48 89 C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 C7 C1 ?? ?? ?? ?? 48 89 C2 B8 ?? 
            ?? ?? ?? 48 89 D7 F2 AE 48 89 C8 48 F7 D0 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 48 01 D0 
            66 C7 00 ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89 
            C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? 48 8D 
            85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 83 E8 ?? 89 05 ?? ?? ?? ?? 
            48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? 
            ?? ?? 0F 85 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 
            48 8B 4D ?? 64 48 33 0C 25 ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? C9 C3 
        }

        $subvert_grub_1 = {
            55 48 89 E5 48 81 EC ?? ?? ?? ?? 64 48 8B 04 25 ?? ?? ?? ?? 48 89 45 ?? 31 C0 48 B8 
            ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 
            ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? 
            ?? ?? ?? 48 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? 
            ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 
            ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 
            ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? 66 C7 85 ?? ?? FF FF ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? 
            ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 
            48 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 48 B8 ?? ?? 
            ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? 
            ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? 
            ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8
        }

        $subvert_grub_2 = { 
            48 89 85 ?? ?? ?? ?? 66 C7 85 ?? ?? FF FF ?? ?? 48 B8 ?? ?? ?? 
            ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 
            48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? 
            ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? 
            ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48 
            8B 85 ?? ?? ?? ?? 48 89 C1 BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 4C 8D 85 ?? ?? 
            ?? ?? 48 8D BD ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85 ?? ?? 
            ?? ?? 48 8D B5 ?? ?? ?? ?? 56 48 8D B5 ?? ?? ?? ?? 56 4D 89 C1 49 89 F8 BE ?? ?? ?? 
            ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 
            E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? 
            ?? ?? 0F 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 B9 ?? 
            ?? ?? ?? ?? ?? ?? ?? 48 89 08 C7 40 ?? ?? ?? ?? ?? C6 40 ?? ?? 48 8B 85
        }

        $subvert_grub_3 = { 
            48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? 
            ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 85 ?? ?? ?? 
            ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 85 ?? ?? ?? 
            ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 ?? EB ?? 48 8D 85 ?? 
            ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 
            85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 
            48 83 BD ?? ?? ?? ?? ?? 74 ?? 4C 8D 85 ?? ?? ?? ?? 48 8D BD ?? ?? ?? ?? 48 8D 8D ?? 
            ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8D B5 ?? ?? ?? ?? 56 48 8D B5 
            ?? ?? ?? ?? 56 4D 89 C1 49 89 F8 BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 48 83 C4 ?? EB ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? 
            ?? 48 83 BD ?? ?? ?? ?? ?? 74 ?? 4C 8D 85 ?? ?? ?? ?? 48 8D BD ?? ?? ?? ?? 48 8D 8D 
            ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8D B5 ?? ?? ?? ?? 56 48 8D 
            B5 ?? ?? ?? ?? 56 4D 89 C1 49 89 F8 BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 48 83 C4 ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 8B 
            55 ?? 64 48 33 14 25 ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? C9 C3 
        }

    condition:
        uint32(0) == 0x464C457F and
        (
            $search_files and
            (all of ($encrypt_files_*)) and
            (all of ($subvert_grub_*))
        )
}
