rule malw_likseput_backdoor_pdb {
     
    meta:
        id = "2MKvm0UfUP0J9yiGngV2z6"
        fingerprint = "v1_sha256_2afc4b7e6a5f0d9fed9a075aebaac8157e843c83c55c3f2255431bb6a03459ec"
        version = "1.0"
        date = "2011-03-26"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Likseput backdoor based on the PDB"
        category = "INFO"
        reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/bkdr_likseput.e"
        hash = "993b36370854587f4eef3366562f01ab87bc4f7b88a21f07b44bd5051340386d"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Likseput"
        actor_group = "Unknown"

     strings:

         $pdb = "\\work\\code\\2008-7-8muma\\mywork\\winInet_winApplication2009-8-7\\mywork\\aaaaaaa\\Release\\aaaaaaa.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 40KB and
         any of them
}
