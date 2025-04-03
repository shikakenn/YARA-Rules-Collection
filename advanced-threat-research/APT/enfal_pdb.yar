rule enfal_pdb
{
    meta:
        id = "68NdvGGygGG1Oy5hLmfMRd"
        fingerprint = "v1_sha256_1f7785a4c54981c3e7cb417718312e0ed82132b9bd9288f7b0f322cbeafbaecd"
        version = "1.0"
        date = "2013-08-27"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Enfal malware"
        category = "MALWARE"
        malware_type = "BACKDOOR"
        actor_type = "APT"
        reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/enfal"
        hash = "6756808313359cbd7c50cd779f809bc9e2d83c08da90dbd80f5157936673d0bf"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Enfal"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\DllServiceTrojan.pdb"
         $pdb1 = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\ServiceDll.pdb"
         $pdb2 = "\\Release\\ServiceDll.pdb"
         $pdb3 = "\\muma\\0511\\Release\\ServiceDll.pdb"
         $pdb4 = "\\programs\\LuridDownLoader\\LuridDownloader for Falcon\\ServiceDll\\Release\\ServiceDll.pdb"
     
     condition:

         uint16(0) == 0x5a4d and
         filesize < 150KB and
         any of them
}
