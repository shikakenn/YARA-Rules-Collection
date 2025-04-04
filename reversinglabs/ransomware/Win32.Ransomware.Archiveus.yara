import "pe"

rule Win32_Ransomware_Archiveus : tc_detection malicious
{
    meta:
        id = "7cyP2jQ12eEtS46oAhlEcK"
        fingerprint = "v1_sha256_2b8a42b98ab3e8b97d2e226e979f342a6a72f21d8f068f59c21ad95764077f8a"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Archiveus ransomware."
        category = "MALWARE"
        malware = "ARCHIVEUS"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Archiveus"
        tc_detection_factor = 5

    strings:

        $entry_point = {
            68 ?? ?? 40 00 E8 ?? ?? ?? FF
        }

        $dump_instruction = {
            8B 3D ?? ?? ?? ?? 6A ?? FF D7 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 
            74 ?? 8B 46 ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D0 8D 4D ?? FF 15 ?? ?? ?? ?? 
            50 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8D 4D ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 
            ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 C4 ?? 6A ?? FF D7 FF 15 ?? ?? ?? ?? E9 ?? ?? 
            ?? ?? 8D 4D ?? 51 FF 15 ?? ?? ?? ?? 8D 55 ?? 6A ?? 52 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? 
            ?? ?? 6A ?? 6A ?? 6A ?? 8D 45 ?? 68 ?? ?? ?? ?? 8D 4D ?? 50 51 FF D3 50 8D 55 ?? 8D 
            45 ?? 52 50 FF D3 50 FF 15 
        }

        $extension_rule = {
            8B 13 6A ?? 68 ?? ?? ?? ?? 52 50 FF 15 ?? ?? ?? ?? D9 85 ?? ?? ?? ?? DB 85 ?? ?? ?? 
            ?? DD 9D ?? ?? ?? ?? DC 8D ?? ?? ?? ?? DF E0 A8 ?? 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? 
            ?? DC 05 ?? ?? ?? ?? DF E0 A8 ?? 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 4D ?? 89 45 
            ?? FF 15 ?? ?? ?? ?? 8B 46 ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D0 8D 4D ?? FF 
            15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D0 8D 4D ?? FF 15 ?? ?? ?? ?? 
            50 6A ?? 6A ?? 6A ?? FF 15 
        }

        $instruction_string = "INSTRUCTIONS HOW TO GET YOUR FILES BACK.txt" wide

    condition:
        uint16(0) == 0x5A4D and ($entry_point at pe.entry_point) and $dump_instruction and $extension_rule and $instruction_string

}
