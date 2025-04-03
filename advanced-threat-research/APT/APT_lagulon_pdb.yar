rule apt_lagulon_trojan_pdb {
     
    meta:
        id = "5dEV2PIfTZmPS5ogKi8d7v"
        fingerprint = "v1_sha256_dad04c2deb990f253f952b768b74349dc9afb5f6db91ea3afff889f4c9f3230b"
        version = "1.0"
        date = "2013-08-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect trojan Lagulon based on PDB"
        category = "MALWARE"
        malware_type = "TROJAN"
        actor_type = "APT"
        reference = "https://www.cylance.com/operation-cleaver-cylance"
        hash = "e401340020688cdd0f5051b7553815eee6bc04a5a962900883f1b3676bf1de53"
        rule_version = "v1"
        malware_family = "Trojan:W32/lagulon"
        actor_group = "Unknown"

     strings:

         $pdb = "\\proj\\wndTest\\Release\\wndTest.pdb"

     condition:

         uint16(0) == 0x5a4d and 
          filesize < 50KB and 
          any of them
}
