rule MALWARE_blackPOS_pdb {
     
    meta:
        id = "5MP8PxGOlz3yTnmQIdx9mK"
        fingerprint = "v1_sha256_d8f3fa380ca15f0fae432849b8c16cb8a0a9d1427d3e72fbf89cbbd63b0849c9"
        version = "1.0"
        date = "2014-01-24"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "BlackPOS PDB"
        category = "INFO"
        reference = "https://en.wikipedia.org/wiki/BlackPOS_Malware"
        hash = "5a963e8aca62f3cf5872c6bff02d6dee0399728554c6ac3f5cb312b2ba7d7dbf"
        rule_version = "v1"
        malware_family = "Pos:W32/BlackPos"
        actor_group = "Unknown"

     strings:

          $pdb = "\\Projects\\Rescator\\MmonNew\\Debug\\mmon.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 300KB and
         any of them
}
