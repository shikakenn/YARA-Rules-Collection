rule Final1stspy_PDB
{
    meta:
        id = "4VAcFLnv7APnk7BSGw6n4c"
        fingerprint = "v1_sha256_111b3db7ae3f0e869bfd5100351402a2aa4ff8e8bda2e5fdf40ae95b4a52d520"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mikesxrs"
        description = "PDB Path in  malware"
        category = "INFO"
        reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-nokki-almost-ties-the-knot-with-dogcall-reaper-group-uses-new-malware-to-deploy-rat/"

strings:
    $STR1= "E:\\Final Project(20180108)\\Final1stspy\\LoadDll\\Release\\LoadDll.pdb"
    $STR2= "E:\\Final Project(20180108)\\Final1stspy\\hadowexecute – Copy\\Release\\hadowexecute.pdb"
    $STR3= "E:\\Final Project(20180108)\\Final1stspy\\"

    
  condition: 
    any of them

}
