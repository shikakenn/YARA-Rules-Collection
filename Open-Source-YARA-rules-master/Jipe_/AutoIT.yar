rule AutoIt : packer
{
    meta:
        id = "58wRB4NwfJaT5T7nljYXCf"
        fingerprint = "v1_sha256_bfe726f71e28ddab64120894a9b5d12af340664f45390b3ee39b746f63534338"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "AutoIT packer"
        category = "INFO"
        filetype = "memory"

    strings:	
        $a = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support."

    condition:
        $a
}
