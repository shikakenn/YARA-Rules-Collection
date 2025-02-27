rule kartoxa_malware_pdb {

    meta:
        id = "4A48oFDFHayTn5xM7KVuaZ"
        fingerprint = "v1_sha256_6e1810af386f3aada4cd1d72f76d8210d201808c8fe1d21d379ff1a825d93710"
        version = "1.0"
        date = "2010-10-09"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Kartoxa POS based on the PDB"
        category = "INFO"
        reference = "https://securitynews.sonicwall.com/xmlpost/guatambu-new-multi-component-infostealer-drops-kartoxa-pos-malware-apr-08-2016/"
        hash = "86dd21b8388f23371d680e2632d0855b442f0fa7e93cd009d6e762715ba2d054"
        rule_version = "v1"
        malware_family = "Pos:W32/Kartoxa"
        actor_group = "Unknown"

     strings:
     
        $pdb = "\\vm\\devel\\dark\\mmon\\Release\\mmon.pdb"
         
    condition:

        uint16(0) == 0x5a4d and
         filesize < 200KB and
         any of them
}
