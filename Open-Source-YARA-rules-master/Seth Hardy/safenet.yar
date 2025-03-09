private rule SafeNetCode : SafeNet Family 
{
    meta:
        id = "5tNw6kkumCIc35qtnuZEK9"
        fingerprint = "v1_sha256_f06ea4fe7cb75506024fafe2a8cdae4bc189b78fe50cfd5d58c60168c9e232f9"
        version = "1.0"
        modified = "2014-07-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "SafeNet code features"
        category = "INFO"

    strings:
        // add edi, 14h; cmp edi, 50D0F8h
        $ = { 83 C7 14 81 FF F8 D0 40 00 }
    condition:
        any of them
}

private rule SafeNetStrings : SafeNet Family
{
    meta:
        id = "7KqPYdbYSUN4UTxPSLE5aI"
        fingerprint = "v1_sha256_319ddfce61a9382a354f5b17de78d3b47760b83c2594a503d909cd7a4bebc2be"
        version = "1.0"
        modified = "2014-07-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Strings used by SafeNet"
        category = "INFO"

    strings:
        $ = "6dNfg8Upn5fBzGgj8licQHblQvLnUY19z5zcNKNFdsDhUzuI8otEsBODrzFCqCKr"
        $ = "/safe/record.php"
        $ = "_Rm.bat" wide ascii
        $ = "try\x0d\x0a\x09\x09\x09\x09  del %s" wide ascii
        $ = "Ext.org" wide ascii
        
    condition:
        any of them

}

rule SafeNet : Family
{
    meta:
        id = "6QaLV79g6Icr6FOJ1riW2m"
        fingerprint = "v1_sha256_dd6292284ee46802926a1131e4e8ebf3c0fcc1587ea3e7e716b5757aaa5771dc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "SafeNet family"
        category = "INFO"

    condition:
        SafeNetCode or SafeNetStrings
        
}
