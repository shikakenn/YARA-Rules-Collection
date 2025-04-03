rule Sengoku_PDB
{
    meta:
        id = "7EbwdJoyzBqtb7TyXVXtsF"
        fingerprint = "v1_sha256_e8014b9582008c4ba8bea7f86a5c65fb3d593b42c3af077e044cb894d70037c0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "@X0RC1SM"
        Description = "Looking for unique PDB"
        Reference = "http://artemonsecurity.com/snake_whitepaper.pdf"
        Date = "2017-10-28"

    strings:    
        $PDB1 = "d:\\proj\\cn\\fa64\\sengoku\\_bin\\sengoku\\win32_debug\\sengoku_Win32.pdb"  ascii wide nocase
        $PDB2 = "d:\\proj\\cn\\fa64\\sengoku\\" ascii wide nocase
        $PDB3 = "\\sengoku_Win32.pdb" ascii wide nocase
    condition:
        any of them
}










