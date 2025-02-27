rule apt_hikit_rootkit {
     
    meta:
        id = "16rOQ49r86sj57VY0g7bbg"
        fingerprint = "v1_sha256_8a425ababdfbe95bd8ac7d4f519be16c0f1fd0b7eea2874124db2f00dd6eb56d"
        version = "1.0"
        date = "2012-08-20"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the rootkit hikit based on PDB"
        category = "INFO"
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
