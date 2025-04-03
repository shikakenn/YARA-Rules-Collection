rule js_downloader_gootloader : downloader
{
    meta:
        id = "7VJrhQwv07HWtEFJ9GA7Di"
        fingerprint = "v1_sha256_f021fb54f5932115d0c826c6739ca90867db51e5d27279e7a78caba277e01b5e"
        version = "1.0"
        date = "2021-02-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "HP Threat Research @HPSecurity"
        description = "JavaScript downloader known to deliver Gootkit or REvil ransomware"
        category = "INFO"
        reference = "https://github.com/hpthreatresearch/tools/blob/main/gootloader/js_downloader_gootloader.yar"
        filetype = "JavaScript"
        maltype = "Downloader"

  strings:
    $a = "function"
    $b1 = "while"
    $b2 = "if"
    $b3 = "else"
    $b4 = "return"
    $c = "charAt"
    $d = "substr"
    $e1 = "\".+"
    $e2 = "\\=\\\""
    $e3 = " r,"
    $e4 = "+;\\\""
    $f = /(\w+\[\w+\]\s+=\s+\w+\[\w+\[\w+\]\];)/

  condition:
    #a > 8 and #a > (#b4 + 3) and all of ($b*) and ($c or $d) and any of ($e*) and $f and filesize < 8000
}
