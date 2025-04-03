private rule cxpidCode : cxpid Family 
{
    meta:
        id = "5TFDPZZaZuuLKU49XRsgHg"
        fingerprint = "v1_sha256_77c7a2bc09934e1979401d5c8da9d57eb730489e4036b3781af6abb9bf5f9912"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "cxpid code features"
        category = "INFO"

    strings:
        $entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }
    
    condition:
        any of them
}

private rule cxpidStrings : cxpid Family
{
    meta:
        id = "2RLcJ4rmSXdwcoliXzhnJe"
        fingerprint = "v1_sha256_227177bb33ff13b95bfc73bc702e5285e8f37bafa1997465b16fb2cb2265c68b"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "cxpid Identifying Strings"
        category = "INFO"

    strings:
        $ = "/cxpid/submit.php?SessionID="
        $ = "/cxgid/"
        $ = "E21BC52BEA2FEF26D005CF"
        $ = "E21BC52BEA39E435C40CD8"
        $ = "                   -,L-,O+,Q-,R-,Y-,S-"
        
    condition:
       any of them
}

rule cxpid : Family
{
    meta:
        id = "x9vwGVUfzLRJ6vaDgEIiO"
        fingerprint = "v1_sha256_1fb5a01b3bc1cadf9ab2bf7d599e505d6c69ab77e958e8c19085cc11ca8716fb"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "cxpid"
        category = "INFO"

    condition:
        cxpidCode or cxpidStrings
}
