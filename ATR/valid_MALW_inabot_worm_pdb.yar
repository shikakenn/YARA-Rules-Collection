rule malw_inabot_worm
{
    meta:
        id = "6eNUmWsdQXXZWFPbtSFJ3i"
        fingerprint = "v1_sha256_70485de4e071b684faa87484ce2a53a8b2a29d0a2954e785b858c7ff1d908de0"
        version = "1.0"
        date = "2013-04-19"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect inabot worm based on PDB"
        category = "INFO"
        reference = "http://verwijderspyware.blogspot.com/2013/04/elimineren-w32inabot-worm-hoe-te.html"
        hash = "c9c010228254aae222e31c669dda639cdd30695729b8ef2b6ece06d899a496aa"
        rule_version = "v1"
        malware_family = "Worm:W32/Inabot"
        actor_group = "Unknown"

     strings:

         $pdb = "\\trasser\\portland.pdb"
         $pdb1 = "\\mainstream\\archive.pdb"

 condition:

         uint16(0) == 0x5a4d and
         filesize < 180KB and
         any of them
}
