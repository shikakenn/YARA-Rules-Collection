rule Greenbug_PDB
{
    meta:
        id = "3FcxvtbSODtzxXhK4mp5ki"
        fingerprint = "v1_sha256_b73a4db43674f6286b0ef6cec10f44f4cde121fd5528a59220c965d8b7650feb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "mikesxrs"
        Description = "Looking for unique PDB"
        Reference = "https://researchcenter.paloaltonetworks.com/2017/07/unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group/"
        Reference2 = "http://www.clearskysec.com/greenbug/"
        Date = "2017-04-05"

  strings:
            $PDB1 = "C:\\Users\\Void\\Desktop\\v 10.0.194\\x64\\Release\\swchost.pdb" ascii wide nocase
        $PDB2 = "C:\\Users\\Void\\Desktop\\" ascii wide nocase
            $PDB3 = "\\Release\\swchost.pdb" ascii wide nocase
    condition:
        any of them
}
