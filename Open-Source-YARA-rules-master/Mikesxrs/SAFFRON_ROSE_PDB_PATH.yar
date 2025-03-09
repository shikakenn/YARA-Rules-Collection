rule SAFFRON_ROSE_PDB_PATH 
{
    meta:
        id = "1oCLy28JxxORwlAxXFgUu9"
        fingerprint = "v1_sha256_0068a106bc310d1709626ea5498cbeceb0d0df82a41490d1f51d000a5f8c60f8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "@X0RC1SM"
        Description = "Looking for unique pdb path"
        Reference = "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-operation-saffron-rose.pdf"

    strings:
        $PDB1 = "d:\\svn\\Stealer\\source\\Stealer\\Stealer\\obj\\x86\\Release\\Stealer.pdb"
        $PDB2 = "f:\\Projects\\C#\\Stealer\\source\\Stealer\\Stealer\\obj\\x86\\Release\\Stealer.pdb"
    condition:
        any of them
}
