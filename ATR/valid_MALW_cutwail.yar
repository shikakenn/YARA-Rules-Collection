rule malw_cutwail_pdb {

    meta:
        id = "5fQVO1m3TSrFxwZ7Z9CnW0"
        fingerprint = "v1_sha256_f53626e6085509ddf9268b69e54a138e64cd5d3fbad119e6e9473179decd7927"
        version = "1.0"
        date = "2008-04-16"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect cutwail based on the PDB"
        category = "INFO"
        reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/CUTWAIL"
        hash = "d702f823eefb50d9ea5b336c638f65a40c2342f8eb88278da60aa8a498c75010"
        rule_version = "v1"
        malware_family = "Botnet:W32/Cutwail"
        actor_group = "Unknown"

     strings:

         $pdb = "\\0bulknet\\FLASH\\Release\\flashldr.pdb"
     
     condition:

         uint16(0) == 0x5a4d and
         filesize < 440KB and
         any of them
}
