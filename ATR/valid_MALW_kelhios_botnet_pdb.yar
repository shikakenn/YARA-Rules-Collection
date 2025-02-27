rule kelihos_botnet_pdb {
     
    meta:
        id = "6BIzvRU25MQSIVuPYw2XZj"
        fingerprint = "v1_sha256_f60fb85161f86653f390b444d568da24cf07b3be99856230156741e8451e2a3f"
        version = "1.0"
        date = "2013-09-04"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Kelihos malware based on PDB"
        category = "INFO"
        reference = "https://www.malwaretech.com/2017/04/the-kelihos-botnet.html"
        hash = "f0a6d09b5f6dbe93a4cf02e120a846073da2afb09604b7c9c12b2e162dfe7090"
        rule_version = "v1"
        malware_family = "Botnet:W32/Kelihos"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Only\\Must\\Not\\And.pdb"
         $pdb1 = "\\To\\Access\\Do.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 1440KB and
         any of them
}
