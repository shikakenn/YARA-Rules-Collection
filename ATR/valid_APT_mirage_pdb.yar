rule apt_mirage_pdb {
         
    meta:
        id = "50ulHH7APU17UdmZNIpQCS"
        fingerprint = "v1_sha256_cb88dc787d9964451ea93f5574d9c73ae6a820d81e20d41c3c8ee44c3fee032d"
        version = "1.0"
        date = "2012-09-18"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Mirage samples based on PDB"
        category = "INFO"
        reference = "https://www.secureworks.com/research/the-mirage-campaign"
        hash = "0107a12f05bea4040a467dd5bc5bd130fd8a4206a09135d452875da89f121019"
        rule_version = "v1"
        malware_family = "Trojan:W32/Mirage"
        actor_group = "Unknown"

    strings:

         $pdb = "\\MF-v1.2\\Server\\Debug\\Server.pdb"
         $pdb1 = "\\fox_1.2 20110307\\MF-v1.2\\Server\\Release\\MirageFox_Server.pdb"

    condition:

        uint16(0) == 0x5a4d and
         filesize < 150KB and
         any of them
}
