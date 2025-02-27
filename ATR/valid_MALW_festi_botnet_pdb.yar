rule festi_botnet_pdb {
     
    meta:
        id = "6IE4fRb2MDuNscWeII9yj7"
        fingerprint = "v1_sha256_46e2576900fe94d614a683d4f09079b7ac78654079b2e558d076bcb42db4bf11"
        version = "1.0"
        date = "2013-03-04"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Festi botnet based on PDB"
        category = "INFO"
        reference = "https://www.welivesecurity.com/2012/05/11/king-of-spam-festi-botnet-analysis/"
        hash = "e55913523f5ae67593681ecb28d0fa1accee6739fdc3d52860615e1bc70dcb99"
        rule_version = "v1"
        malware_family = "Botnet:W32/Festi"
        actor_group = "Unknown"

     strings:

         $pdb = "\\eclipse\\botnet\\drivers\\Bin\\i386\\kernel.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 80KB and
         any of them
}
