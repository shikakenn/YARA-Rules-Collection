rule apt_hikit_rootkit {
     
    meta:
        id = "3KBb5mCAY5jEVD8qjISrfT"
        fingerprint = "v1_sha256_8a425ababdfbe95bd8ac7d4f519be16c0f1fd0b7eea2874124db2f00dd6eb56d"
        version = "1.0"
        date = "2012-08-20"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the rootkit hikit based on PDB"
        category = "MALWARE"
        malware_type = "ROOTKIT"
        actor_type = "CRIMEWARE"
        reference = "https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-1.html"
        rule_version = "v1"
        malware_family = "Rootkit:W32/Hikit"
        actor_group = "Unknown"

     strings:

         $pdb = "\\JmVodServer\\hikit\\bin32\\RServer.pdb"
         $pdb1 = "\\JmVodServer\\hikit\\bin32\\w7fw.pdb"
         $pdb2 = "\\JmVodServer\\hikit\\bin32\\w7fw_2k.pdb"
         $pdb3 = "\\JmVodServer\\hikit\\bin64\\w7fw_x64.pdb"

     condition:

          uint16(0) == 0x5a4d and 
          filesize < 100KB and 
          any of them
}
