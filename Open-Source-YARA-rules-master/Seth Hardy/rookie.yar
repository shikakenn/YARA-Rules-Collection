private rule RookieCode : Rookie Family 
{
    meta:
        id = "29lrl3eR5V516tyoZSyUBB"
        fingerprint = "v1_sha256_29ac552f1400ebcc828c67980d034406bf32b9d1f83fec31a5c8f1422fbd030d"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Rookie code features"
        category = "INFO"

    strings:
        // hidden AutoConfigURL
        $ = { C6 ?? ?? ?? 41 C6 ?? ?? ?? 75 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 43 C6 ?? ?? ?? 6F C6 ?? ?? ?? 6E C6 ?? ?? ?? 66 }
        // hidden ProxyEnable
        $ = { C6 ?? ?? ?? 50 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 78 C6 ?? ?? ?? 79 C6 ?? ?? ?? 45 C6 ?? ?? ?? 6E C6 ?? ?? ?? 61 }
        // xor on rand value?
        $ = { 8B 1D 10 A1 40 00 [18] FF D3 8A 16 32 D0 88 16 }

    condition:
        any of them
}

private rule RookieStrings : Rookie Family
{
    meta:
        id = "6m8jhT4msSb3uuoAAFphbW"
        fingerprint = "v1_sha256_e170b641e42988dbf05b0762a65bd385e0116a13e43774d1206458e393bc39a2"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Rookie Identifying Strings"
        category = "INFO"

    strings:
        $ = "RookIE/1.0"
        
    condition:
       any of them
}

rule Rookie : Family
{
    meta:
        id = "4H1GPIPJU0Qy77NVurhqAf"
        fingerprint = "v1_sha256_94ce9753bb4be9d031913c3545823b1ce960b2089307c4c883882d9b1543bb39"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Rookie"
        category = "INFO"

    condition:
        RookieCode or RookieStrings
}
