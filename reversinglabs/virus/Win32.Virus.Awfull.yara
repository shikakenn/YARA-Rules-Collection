import "pe"

rule Win32_Virus_Awfull : tc_detection malicious
{
    meta:
        id = "1njVu0AT4UiCo0QY7SlmHU"
        fingerprint = "v1_sha256_84a4faee4cbbb3387ad25bd9230c6482b8db461bc008312bc782f23e3df2eae3"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Awfull virus."
        category = "MALWARE"
        malware = "AWFULL"
        tc_detection_type = "Virus"
        tc_detection_name = "Awfull"
        tc_detection_factor = 5

    strings:
        $awfull_body = {
              60 E8 ?? 00 00 00 8B 64 24 08 EB ?? [0-256]
              33 D2 64 FF 32 64 89 22 33 C0 C7 00 00 00 00 00 33 D2 64 8F 02
              5A 64 (8B 0D | 67 8B 0E ) 14 00 [0-2] E3 03 FA    
              EB FD 61 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 0B ED 74 ?? 
              [0-128] (BE | 8B 35) ?? ?? ?? ?? 03 F5 B9 ?? ?? ?? ??    
              56 5F AC F6 D0 AA 49 E3 02 EB F7
        }
        
    condition:
        uint16(0) == 0x5A4D and 
        ($awfull_body at pe.entry_point)
}
