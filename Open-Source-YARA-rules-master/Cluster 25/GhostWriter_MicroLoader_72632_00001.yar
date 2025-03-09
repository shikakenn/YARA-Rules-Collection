rule GhostWriter_MicroLoader_72632_00001 {
    meta:
        id = "4K9Djgw2g7DBjWU29AlN80"
        fingerprint = "v1_sha256_f4c22e6f16374e26c6b3d7bdf49dfac6e3daab6e8ac42045a107f68ce61ba2b1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cluster25"
        description = "NA"
        category = "INFO"
        report = "HTTPS://BLOG.CLUSTER25.DUSKRISE.COM/2022/03/08/GHOSTWRITER-UNC1151-ADOPTS-MICROBACKDOOR-VARIANTS-IN-CYBER-OPERATIONS-AGAINST-TARGETS-IN-UKRAINE"
        hash1 = "e97f1d6ec1aa3f7c7973d57074d1d623833f0e9b1c1e53f81af92c057a1fdd72"
        tlp = "white"

strings:
$ = "ajf09aj2.dll" fullword wide
$ = "regsvcser" fullword ascii
$ = "X l.dlT" fullword ascii
$ = "rtGso9w|4" fullword ascii
$ = "ajlj}m${<" fullword ascii
condition: (uint16(0) == 0x5a4d and all of them)
}
