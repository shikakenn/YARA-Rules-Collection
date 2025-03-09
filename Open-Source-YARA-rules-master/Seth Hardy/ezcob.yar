private rule EzcobStrings : Ezcob Family
{
    meta:
        id = "6rsie7wFDtfPCSUs5slxoD"
        fingerprint = "v1_sha256_0558f3c3d372718db19ca44823fe5e4e7e9611d1e4c5fb5be43b8cb67abedcc3"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Ezcob Identifying Strings"
        category = "INFO"

    strings:
        $ = "\x12F\x12F\x129\x12E\x12A\x12E\x12B\x12A\x12-\x127\x127\x128\x123\x12"
        $ = "\x121\x12D\x128\x123\x12B\x122\x12E\x128\x12-\x12B\x122\x123\x12D\x12"
        $ = "Ezcob" wide ascii
        $ = "l\x12i\x12u\x122\x120\x121\x123\x120\x124\x121\x126"
        $ = "20110113144935"
        
    condition:
       any of them
}

rule Ezcob : Family
{
    meta:
        id = "JIjZ7w9MAcdDUou9rw7f3"
        fingerprint = "v1_sha256_bf6b995288056f75e3bd163a02bdc6e39e8068dd4090026d00662e13e8ae7ba6"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Ezcob"
        category = "INFO"

    condition:
        EzcobStrings
}
