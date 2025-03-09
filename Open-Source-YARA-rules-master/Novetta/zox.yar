rule zox
{
    meta:
        id = "7QWshKueD3l71PoC63kDvS"
        fingerprint = "v1_sha256_c74440bba25f17219c4baecd021214ac9d8364cfadb62d893bb971d258903983"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Novetta"
        Reference = "https://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf"

    strings:
        $url ="png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58"

    condition:
        $url
}
