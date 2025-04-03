rule KONNI_PDB
{
    meta:
        id = "14bUowYYsLtMr3Kmz66pne"
        fingerprint = "v1_sha256_1ba009184d73904e5a610cc1af7d5c3bb261b0a3fe93cd6efeeb09a183d00421"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mikesxrs"
        description = "PDB Path in  malware"
        category = "INFO"
        reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-new-konni-malware-attacking-eurasia-southeast-asia/"

strings:
    $STR1= "C:\\Users\\zeus\\Documents\\Visual Studio 2010\\Projects\\virus-dropper\\Release\\virus-dropper.pdb" 
    $STR2= "C:\\Users\\zeus\\Documents\\Visual Studio 2010\\Projects\\"
    $STR3= "\\virus-dropper\\Release\\virus-dropper.pdb"
    
  condition: 
    any of them

}
