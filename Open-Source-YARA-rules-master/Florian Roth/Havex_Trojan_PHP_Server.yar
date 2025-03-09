rule Havex_Trojan_PHP_Server
    {
    meta:
        id = "2cZkGNDnfzbYBVAgetZZp5"
        fingerprint = "v1_sha256_c68c96c26c7e3f9d030d604c7c1121d4dd619bd79377949021f8c2213bdbb8ef"
        version = "1.0"
        date = "2014-06-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects the PHP server component of the Havex RAT"
        category = "INFO"
        reference = "http://goo.gl/GO5mB1"

    strings:
        $s1 = "havex--></body></head>"
        $s2 = "ANSWERTAG_START"
        $s3 = "PATH_BLOCKFILE"
    condition:
        all of them
}
