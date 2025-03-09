rule CN_group_PDB
{
    meta:
        id = "78R2PpEI7eNvYXAMScM7am"
        fingerprint = "v1_sha256_42b0752848c957c7941ba8fe3f52876c361dbed6eab52b4af1b2c5151a806987"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "mikesxrs"
        Description = "Looking for unique 1937CN group PDB"
        Reference = "https://www.votiro.com/single-post/2017/08/23/Votiro-Labs-exposed-a-new-hacking-campaign-targeting-Vietnamese-organisations-using-a-weaponized-Word-documents"
        Date = "2017-08-23"

    strings:
        $PDB1 = "G:\\Work\\Bison\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii wide nocase
        $PDB2 = "G:\\Work\\Bison\\" ascii wide nocase
        $PDB3 = "\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii wide nocase
    condition:
        any of them
}	
