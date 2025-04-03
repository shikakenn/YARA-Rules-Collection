rule APT28_SkinnyBoy_Dropper: RUSSIAN THREAT ACTOR {
    meta:
        id = "6XFRTDj7be0uwLNYQhRP0Z"
        fingerprint = "v1_sha256_5671963b65e7b005b97b5f5363c28438590e640a39a16c24b7439a7eda338fd1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cluster25"
        description = "NA"
        category = "INFO"
        report = "HTTPS://21649046.FS1.HUBSPOTUSERCONTENT-NA1.NET/HUBFS/21649046/2021-05_FANCYBEAR.PDF"
        hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"

strings:
$ = "cmd /c DEL " ascii
$ = " \"" ascii
$ = {8a 08 40 84 c9 75 f9}
$ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}
condition:
(uint16(0) == 0x5A4D and all of them)
}
