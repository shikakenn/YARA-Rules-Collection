rule apt_gauss_pdb {
     
    meta:
        id = "6g0yxKd0t9CwBLdLfuy3Sr"
        fingerprint = "v1_sha256_cb20c87ea976f395e000f2c631ffd52b09dca2af37adceafe5be72b37f75a997"
        version = "1.0"
        date = "2012-08-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Gauss based on PDB"
        category = "MALWARE"
        malware_type = "BACKDOOR"
        actor_type = "APT"
        reference = "https://securelist.com/the-mystery-of-the-encrypted-gauss-payload-5/33561/"
        hash = "7b0d0612b4ecc889a901115c2e77776ef0ea65c056b283d12e80f863062cea28"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Gauss"
        actor_group = "Unknown"

     strings:

         $pdb = "\\projects\\gauss\\bin\\release\\winshell.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 550KB and
         any of them
}
