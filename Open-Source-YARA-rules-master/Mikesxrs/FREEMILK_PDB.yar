rule FREEMILK_PDB
{
    meta:
        id = "64lTDYyJSGOE3Hvi1JQDca"
        fingerprint = "v1_sha256_98f206d6222e0fd39a79dfcd49efb37398ee88a78b02ec0ec9fed6446d155efe"
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
        Reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
        Date = "2017-10-05"

  strings:
        $PDB1 = "E:\\BIG_POOH\\Project\\milk\\Release\\milk.pdb" ascii wide nocase
        $PDB2 = "E:\\BIG_POOH\\Project\\Desktop\\milk\\Release\\milk.pdb" ascii wide nocase
        $PDB3 = "E:\\BIG_POOH\\" ascii wide nocase
        $PDB4 = "\\Release\\milk.pdb" ascii wide nocase
        $PDB5 = "F:\\Backup\\2nd\\Agent\\Release\\Agent.pdb"
    condition:
        any of them
}
