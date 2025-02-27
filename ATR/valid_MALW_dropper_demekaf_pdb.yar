rule dropper_demekaf_pdb {
     
    meta:
        id = "5kljgI7Z5OlP0c9x95CufA"
        fingerprint = "v1_sha256_89c0c1da1f8997b12a446c93bbde200e62fac9cab2a9a17147b268d435bdc3b6"
        version = "1.0"
        date = "2011-03-26"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Demekaf dropper based on PDB"
        category = "INFO"
        reference = "https://v.virscan.org/Trojan-Dropper.Win32.Demekaf.html"
        hash = "fab320fceb38ba2c5398debdc828a413a41672ce9745afc0d348a0e96c5de56e"
        rule_version = "v1"
        malware_family = "Dropper:W32/Demekaf"
        actor_group = "Unknown"

      strings:

         $pdb = "\\vc\\res\\fake1.19-jpg\\fake\\Release\\fake.pdb"

      condition:

          uint16(0) == 0x5a4d and
         filesize < 150KB and
         any of them
}
