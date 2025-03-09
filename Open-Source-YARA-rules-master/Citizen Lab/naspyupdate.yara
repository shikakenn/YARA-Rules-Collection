private rule nAspyUpdateCode : nAspyUpdate Family 
{
    meta:
        id = "60lYT0JFoiJ0NKscQh1aT2"
        fingerprint = "v1_sha256_5d6a4dd8d153d315bacb10c259575a936b4ee900db70abf7afd6b36d5be1b965"
        version = "1.0"
        modified = "2014-07-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "nAspyUpdate code features"
        category = "INFO"

    strings:
        // decryption loop in dropper
        $ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }
        
    condition:
        any of them
}

private rule nAspyUpdateStrings : nAspyUpdate Family
{
    meta:
        id = "5obzzVw7wz5EaF89w6k8zd"
        fingerprint = "v1_sha256_b2ff8158a971252f2eab0a64da15d8b4184bd42938f6f58fd861863ad9f5f9b0"
        version = "1.0"
        modified = "2014-07-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "nAspyUpdate Identifying Strings"
        category = "INFO"

    strings:
        $ = "\\httpclient.txt"
        $ = "password <=14"
        $ = "/%ldn.txt"
        $ = "Kill You\x00"
        
    condition:
        any of them
}

rule nAspyUpdate : Family
{
    meta:
        id = "28FhSeibeLCgc5irwgYSfI"
        fingerprint = "v1_sha256_340c0fc4faccaf36b0be639adc15a49d092a03b7bba2f402552d5b33ebc69d03"
        version = "1.0"
        modified = "2014-07-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "nAspyUpdate"
        category = "INFO"

    condition:
        nAspyUpdateCode or nAspyUpdateStrings
}
