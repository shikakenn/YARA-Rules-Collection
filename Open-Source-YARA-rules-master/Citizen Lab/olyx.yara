private rule OlyxCode : Olyx Family 
{
    meta:
        id = "2mweVzncQgSwRIEeIKEKw6"
        fingerprint = "v1_sha256_276eea2a2cf2214bb364110a5ff6841b0977de4d28d637239130a7637b462c2e"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Olyx code tricks"
        category = "INFO"

    strings:
        $six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
        $slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }
        
    condition:
        any of them
}

private rule OlyxStrings : Olyx Family
{
    meta:
        id = "23vUdz5ZbEdAEx5dEdW7Tn"
        fingerprint = "v1_sha256_e315224427a0c8461237f1fa89addc32d47a2813093f64dd8980b09e678e5301"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Olyx Identifying Strings"
        category = "INFO"

    strings:
        $ = "/Applications/Automator.app/Contents/MacOS/DockLight"
       
    condition:
        any of them
}

rule Olyx : Family
{
    meta:
        id = "2h4ztzOdZL7r6xOduDiYxq"
        fingerprint = "v1_sha256_1f05701c0fd155ded5af1b71a591a715e3b9e51d18220b12d145edf73b685add"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Olyx"
        category = "INFO"

    condition:
        OlyxCode or OlyxStrings
}
