private rule Insta11Code : Insta11 Family 
{
    meta:
        id = "6aCePbsszhX4RxWTCQuVtu"
        fingerprint = "v1_sha256_a54393a19457ebd697b5fba77ab8ce0429762deb415d21f43a6b8d3a695bc316"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Insta11 code features"
        category = "INFO"

    strings:
        // jmp $+5; push 423h
        $jumpandpush = { E9 00 00 00 00 68 23 04 00 00 }
    
    condition:
        any of them
}

private rule Insta11Strings : Insta11 Family
{
    meta:
        id = "4gDFLEXVAbcl8DOT3v6ndF"
        fingerprint = "v1_sha256_5b7c1e807b8fdaf292ee40ee36dab8b53ee457bb9251be771d248501a41b22bf"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Insta11 Identifying Strings"
        category = "INFO"

    strings:
        $ = "XTALKER7"
        $ = "Insta11 Microsoft" wide ascii
        $ = "wudMessage"
        $ = "ECD4FC4D-521C-11D0-B792-00A0C90312E1"
        $ = "B12AE898-D056-4378-A844-6D393FE37956"
        
    condition:
       any of them
}

rule Insta11 : Family
{
    meta:
        id = "4PfJJgmlshxnu8LutlC3Je"
        fingerprint = "v1_sha256_106c7247f642340cdc19ec737cd025107a45033f5835c08c02800b9dfff44bc2"
        version = "1.0"
        modified = "2014-06-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Insta11"
        category = "INFO"

    condition:
        Insta11Code or Insta11Strings
}
