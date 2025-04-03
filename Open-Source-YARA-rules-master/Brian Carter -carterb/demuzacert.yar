rule PotentiallyCompromisedCert

{
    meta:
        id = "4hQOZtyfWxeRvO3knajCgI"
        fingerprint = "v1_sha256_21b2332446296bb79b92affc2397fc5a03cb583dec9c3a91d1de640b1f3481ae"
        version = "1.0"
        modified = "July 21, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Search for PE files using cert issued to DEMUZA "
        category = "INFO"
        sample = "7ef8f5e0ca92a0f3a5bd8cdc52236564"
        TLP = "WHITE"

    strings:
        $magic = { 50 4b 03 04 (14 | 0a) 00 }

        $txt1 = "demuza@yandex.ru" nocase
        $txt2 = "https://secure.comodo.net/CPS0C" nocase
        $txt3 = "COMODO CA Limited1"

    condition:
       $magic at 0 and all of ($txt*)
}
