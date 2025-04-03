rule Linux_Worm_ORCSHRED {
    meta:
        id = "TYJPxUW6Iq1KruFrh1Ax7"
        fingerprint = "v1_sha256_bf826e2cb0bc0fef74db1248539b00dfa57a9a9c84c0ab374e6b3f92b02de84e"
        version = "1.0"
        date = "2022-04-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mmuir@cadosecurity.com"
        description = "Detects ORCSHRED worm used in attacks on Ukrainian ICS"
        category = "INFO"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        hash = "43d07f28b7b699f43abd4f695596c15a90d772bfbd6029c8ee7bc5859c2b0861"
        license = "Apache License 2.0"

    strings:
    $a = "is_owner" ascii
    $b = "Start most security mode!" ascii
    $c = "check_solaris" ascii
    $d = "wsol.sh" ascii
    $e = "wobf.sh" ascii
    $f = "disown" ascii
    $g = "/var/log/tasks" ascii
    condition:
        4 of them
}
