rule UNC1222_HermeticWiper_23433_10001 {
    meta:
        id = "3oisJ3qNLYOK2dxjN5qpOu"
        fingerprint = "v1_sha256_bed91eb4bd1dfd20783cfd74111b0f120dc302eea6f06921139bbec2ee0bfc46"
        version = "1.0"
        date = "2022-02-23"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cluster25"
        description = "Detects HermeticWiper variants by internal strings"
        category = "INFO"
        report = "HTTPS://BLOG.CLUSTER25.DUSKRISE.COM/2022/02/24/UKRAINE-ANALYSIS-OF-THE-NEW-DISK-WIPING-MALWARE"
        tlp = "white"
        hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
        hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"

strings:
$ = "tdrv.pdb" fullword ascii
$ = "\\\\.\\EPMNTDRV\\%u" fullword wide
$ = "PhysicalDrive%u" fullword wide
$ = "Hermetica Digital Ltd"
condition:
(uint16(0) == 0x5a4d and all of them)
}
