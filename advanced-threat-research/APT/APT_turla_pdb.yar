rule apt_turla_pdb
{
    meta:
        id = "4XP0pCKjGdZCKOe4SgHzL5"
        fingerprint = "v1_sha256_d519317c936a38f189bf0de908902ec4e3e079c8c7463c8881ceb332c0a82a26"
        version = "1.0"
        date = "2017-05-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect a component of the APT Turla"
        category = "MALWARE"
        malware_type = "BACKDOOR"
        actor_type = "APT"
        reference = "https://attack.mitre.org/groups/G0010/"
        hash = "3b8bd0a0c6069f2d27d759340721b78fd289f92e0a13965262fea4e8907af122"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Turla"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Workshop\\Projects\\cobra\\carbon_system\\x64\\Release\\carbon_system.pdb"

     condition:
     
         uint16(0) == 0x5a4d and
         filesize < 650KB and
         any of them
}
