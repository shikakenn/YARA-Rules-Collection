rule Dridex_P2P_pdb
{
    meta:
        id = "3LoJZW0EexMPubm8usaKnt"
        fingerprint = "v1_sha256_c9c4db48435203cdb882eef8082efd8424bd13f1aa512cfb3082f365b9bc6e83"
        version = "1.0"
        date = "2014-11-29"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Dridex P2P based on the PDB"
        category = "INFO"
        reference = "https://www.us-cert.gov/ncas/alerts/aa19-339a"
        hash = "5345a9405212f3b8ef565d5d793e407ae8db964865a85c97e096295ba3f39a78"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Dridex"
        actor_group = "Unknown"

     strings:

         $pdb = "\\c0da\\j.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 400KB and
         any of them
}
