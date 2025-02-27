rule apt_miniasp_pdb {
     
    meta:
        id = "7fryVXulU2vU0jcyDXEora"
        fingerprint = "v1_sha256_8ee6f93aaae2c48cc5835269fd526371040cd33cc309220f92a150444ba21055"
        version = "1.0"
        date = "2012-07-12"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect MiniASP based on PDB"
        category = "INFO"
        reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
        hash = "42334f2119069b8c0ececfb14a7030e480b5d18ca1cc35f1ceaee847bc040e53"
        rule_version = "v1"
        malware_family = "Trojan:W32/MiniASP"
        actor_group = "Unknown"

     strings:
         
         $pdb = "\\Project\\mm\\Wininet\\Attack\\MiniAsp4\\Release\\MiniAsp.pdb"
         $pdb1 = "\\XiaoME\\AiH\\20120410\\Attack\\MiniAsp3\\Release\\MiniAsp.pdb"
     
     condition:

         uint16(0) == 0x5a4d and
         filesize < 80KB and
         any of them
}
