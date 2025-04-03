rule badpatch_PDB
{
    meta:
        id = "45sgVVPejoSy3cs9yce9QG"
        fingerprint = "v1_sha256_eea9ba462950e7601e51ad0fa69f8288337b860b20ad6af8dacb336c882d40e4"
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
        Reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-badpatch/"
        Date = "2017-10-28"

    strings:    
        $VBP1 = "D:\\000 work\\21.3 GB\\newSpoofKL\\Project1.vbp" ascii wide nocase
        $VBP2 = "Y:\\My Work\\VB 6\\Get Files\\GFiles 14-09-2015 – Working tst only\\Project1.vbp" ascii wide nocase
        $VBP3 = "C:\\Users\\Shady\\Desktop\\only email with slide show\\Project1.vbp" ascii wide nocase
        $VBP4 = "E:\\work here\\ready kl send recent files\\Project1.vbp" ascii wide nocase
        $VBP5 = "Q:\\newPatch\\downloader\\exe site\\shop\\Project1.vbp" ascii wide nocase
        $VBP6 = "J:\\dowloader 2 8\\downloader\\site\\Project1.vbp" ascii wide nocase
        $VBP7 = "W:\\newPatch\\exe vb m103 30 3 2016\\Project1.vbp" ascii wide nocase
    condition:
        all of them
}
