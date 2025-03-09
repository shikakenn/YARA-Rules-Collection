rule Aurora_PDB
{
    meta:
        id = "NIfsoe08puPXWgus3pGMH"
        fingerprint = "v1_sha256_07c1f2f1fa218e3429d5a2aaee66b4e080d0fc5678939f6149dde304e2ed29ea"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Michael Worth"
        description = "PDB path from Arora"
        category = "INFO"
        reference = "https://www.secureworks.com/blog/research-20913"

    strings:
        $PDB1 = "f:\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"
        $PDB2 = "f:\\Aurora_Src\\"
    condition:
        $PDB1 or $PDB2
}
