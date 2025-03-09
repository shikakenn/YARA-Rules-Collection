rule PDB_Arachnophobia
{
    meta:
        id = "7lPcYyZs8wyztEyPEszLsU"
        fingerprint = "v1_sha256_e52eb71fcc475b2b1908f6b46a0cfb10ab93f13b3ac87a7ae2aaf957f33840de"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "mikesxrs"
        Description = "Looking for unique PDB strings"
        Reference = "https://www.threatconnect.com/where-there-is-smoke-there-is-fire-south-asian-cyber-espionage-heats-up/Operation Arachnophobia"
        Date = "2017-10-28"

    strings:
        $PDB1 = "C:\\Users\\Tranchulas\\Documents\\Visual Studio 2008\\Projects\\upload\\Release\\upload.pdb"
        $PDB2 = "C:\\Users\\Cath\\documents\\visual studio 2010\\Projects\\ExtractPDF\\Release\\ExtractPDF.pdb"
        $PDB3 = "C:\\Users\\Cath\\documents\\visual studio 2010\\Projects\\Start\\Release\\Start.pdb"
        $PDB4 = "C:\\Users\\Cert-India\\Documents\\Visual Studio 2008\\Projects\\ufile\\Release\\ufile.pdb"
        $PDB5 = "C:\\Users\\umairaziz27\\Documents\\Visual Studio 2008\\Projects\\usb\\Release\\usb.pdb"
    condition:
        any of them
}
