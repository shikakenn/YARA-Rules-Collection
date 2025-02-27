import "pe"

rule Sodinokobi
{
    meta:
        id = "3kyb0TFDM0bWnzZZgvRQWC"
        fingerprint = "v1_sha256_f25039ac743223756461bbeeb349c674473608f9959bf3c79ce4a7587fde3ab2"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "McAfee ATR team"
        description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
        category = "INFO"
        rule_version = "v1"
        malware_family = "Ransom:W32/Sodinokibi"
        actor_group = "Unknown"

    strings:

        $a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
        $b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

    condition:
    
        all of them
}
