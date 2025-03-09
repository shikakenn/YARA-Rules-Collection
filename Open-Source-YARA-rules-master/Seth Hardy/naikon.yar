private rule NaikonCode : Naikon Family 
{
    meta:
        id = "7WTtIlLkOFyG0JFUCgXcFH"
        fingerprint = "v1_sha256_643a0012bc4bdd26f63da169e756cdd7bc8e41d27c4db245823f43fd55eeae8a"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Naikon code features"
        category = "INFO"

    strings:
        // decryption
        $ = { 0F AF C1 C1 E0 1F } // imul eax, ecx; shl eah, 1fh
        $ = { 35 5A 01 00 00} // xor eax, 15ah
        $ = { 81 C2 7F 14 06 00 } // add edx, 6147fh
    
    condition:
        all of them
}

private rule NaikonStrings : Naikon Family
{
    meta:
        id = "1q9m6Xq6jnED1znLX9O3Yg"
        fingerprint = "v1_sha256_8f0cc38cb2190cbdc0fb38d2baaf33476705230833b803eaa68b1ce8e80e7d7d"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Naikon Identifying Strings"
        category = "INFO"

    strings:
        $ = "NOKIAN95/WEB"
        $ = "/tag=info&id=15"
        $ = "skg(3)=&3.2d_u1"
        $ = "\\Temp\\iExplorer.exe"
        $ = "\\Temp\\\"TSG\""
        
    condition:
       any of them
}

rule Naikon : Family
{
    meta:
        id = "9BpA74J3yyEIU4a4iri27"
        fingerprint = "v1_sha256_3dc3f14bce8ab19572bb59bb269b7ffbb967065e9410f959236507f75b70cff3"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Naikon"
        category = "INFO"

    condition:
        NaikonCode or NaikonStrings
}
