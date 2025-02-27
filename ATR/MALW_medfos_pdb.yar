rule malw_medfos {
     
    meta:
        id = "XUwSjL57ZCsLOVuAzloFf"
        fingerprint = "v1_sha256_1726462a806f5cb3f0b80596623cebc51a7a9f866ded0cb59ea1c43034ce2819"
        version = "1.0"
        date = "2013-04-19"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Medfos trojan based on PDB"
        category = "INFO"
        reference = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=win32%2Fmedfos"
        hash = "3582e242f62598445ca297c389cae532613afccf48b16e9c1dcf1bfedaa6e14f"
        rule_version = "v1"
        malware_family = "Trojan:W32/Medfos"
        actor_group = "Unknown"

     strings:

         $pdb = "\\som\\bytguqne\\jzexsaf\\gyin.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 150KB and
         any of them
}
