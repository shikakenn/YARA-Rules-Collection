rule jRAT_conf : rat 
{
    meta:
        id = "3Xx125wefSON16Q2QraKs6"
        fingerprint = "v1_sha256_03fe6628789c3660c32b697ec3e5735588e8892135c30ff63a5fef72d675a2c9"
        version = "1.0"
        date = "2013-10-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "jRAT configuration"
        category = "INFO"
        filetype = "memory"
        ref1 = "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py"
        ref2 = "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html"

    strings:
        $a = "/port=[0-9]{1,5}SPLIT/" 

    condition: 
        $a
}
