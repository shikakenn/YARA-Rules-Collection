rule REHASHED_PDB
{
    meta:
        id = "5oXy30EhsHAiBQDkbiw1Vt"
        fingerprint = "v1_sha256_a1f9933cd4feb56a5ba2b96ac4697b715e9c6a0974ecd46242ba1f8cd6174852"
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
        Reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
        Date = "2017-09-05"

  strings:
        $PDB1 = "C:\\Users\\hoogle168\\Desktop\\2008Projects\\NewCoreCtrl08\\Release\\NewCoreCtrl08.pdb" ascii wide nocase
        $PDB2 = "C:\\Users\\hoogle168\\" ascii wide nocase
        $PDB3 = "\\NewCoreCtrl08\\Release\\NewCoreCtrl08.pdb" ascii wide nocase
    condition:
        any of them
}
