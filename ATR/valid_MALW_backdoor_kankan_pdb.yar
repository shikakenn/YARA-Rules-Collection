rule backdoor_kankan_pdb {
     
    meta:
        id = "1qCRw4vuJV3sYkQZPUnQlf"
        fingerprint = "v1_sha256_3d2e45631dfca0e76e98eee4bb5c4ce1631906f497c052d8c41cc37637cb2760"
        version = "1.0"
        date = "2013-08-01"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect kankan PDB"
        category = "INFO"
        reference = "https://threatpoint.checkpoint.com/ThreatPortal/threat?threatType=malwarefamily&threatId=650"
        hash = "73f9e28d2616ee990762ab8e0a280d513f499a5ab2cae9f8cf467701f810b98a"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Kankan"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Projects\\OfficeAddin\\INPEnhSvc\\Release\\INPEnhSvc.pdb"
         $pdb1 = "\\Projects\\OfficeAddin\\OfficeAddin\\Release\\INPEn.pdb"
         $pdb2 = "\\Projects\\OfficeAddinXJ\\VOCEnhUD\\Release\\VOCEnhUD.pdb"
 
    condition:

         uint16(0) == 0x5a4d and
         filesize < 500KB and
         any of them
}
