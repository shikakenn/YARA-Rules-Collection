rule troy_malware_campaign_pdb {

    meta:
        id = "4SbO3ISpp1pAOBBkZQSv98"
        fingerprint = "v1_sha256_a64b4aa082c45d1753ad30ba2f67df0ef5b7658c3c99e031ef747eb4e6c7bb00"
        version = "1.0"
        date = "2013-06-23"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Operation Troy based on the PDB"
        category = "INFO"
        reference = "https://www.mcafee.com/enterprise/en-us/assets/white-papers/wp-dissecting-operation-troy.pdf"
        hash = "2ca6b7e9488c1e9f39392e696704ad3f2b82069e35bc8001d620024ebbf2d65a"
        rule_version = "v1"
        malware_family = "Backdoor:W32/OperationTroy"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\SetKey_WinlogOn_Shell_Modify\\BD_Installer\\Release\\BD_Installer.pdb"
         $pdb1 = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\Dll\\Concealment_Troy(Dll)\\Release\\Concealment_Troy.pdb"
     
     condition:

         uint16(0) == 0x5a4d and
         filesize < 500KB and
         any of them
}
