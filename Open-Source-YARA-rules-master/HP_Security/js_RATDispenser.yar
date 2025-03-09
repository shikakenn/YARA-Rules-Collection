rule js_RATDispenser : downloader
{
    meta:
        id = "6fjm2KCPzK1xb4gzTk5Tf"
        fingerprint = "v1_sha256_21dc525eb3ec3f6196a9c3ab676610128ba41b244a22d9d6122c0ab16f5d9bc4"
        version = "1.0"
        date = "2021-05-27"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "HP Threat Research @HPSecurity"
        description = "JavaScript downloader resp. dropper delivering various RATs"
        category = "INFO"
        reference = "https://threatresearch.ext.hp.com/javascript-malware-dispensing-rats-into-the-wild/"
        filetype = "JavaScript"
        maltype = "Downloader"

  strings:
    $a = /{(\d)}/

    $c1 = "/{(\\d+)}/g"
    $c2 = "eval"
    $c3 = "prototype"

    $d1 = "\\x61\\x64\\x6F\\x64\\x62\\x2E"
    $d2 = "\\x43\\x68\\x61\\x72\\x53\\x65\\x74"
    $d3 = "\\x54\\x79\\x70\\x65"

    $e1 = "adodb."
    $e2 = "CharSet"
    $e3 = "Type"

    $f1 = "arguments"
    $f2 = "this.replace"

  condition:
    #a > 50 and all of ($c*) and (any of ($d*) or any of ($e*)) and all of ($f*) and filesize < 2MB
}
