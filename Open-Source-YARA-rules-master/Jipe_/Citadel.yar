rule citadel13xy : banker
{
    meta:
        id = "1jgcmE0LR6WFZM3t8Z8gAf"
        fingerprint = "v1_sha256_d8fecb4722f899417a183223f1b1c749934203f844b08438bd5af14815450543"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Citadel 1.5.x.y trojan banker"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "Coded by BRIAN KREBS for personnal use only. I love my job & wife."
        $b = "http://%02x%02x%02x%02x%02x%02x%02x%02x.com/%02x%02x%02x%02x/%02x%02x%02x%02x%02x.php"
        $c = "%BOTID%"
        $d = "%BOTNET%"
        $e = "cit_video.module"
        $f = "bc_remove"
        $g = "bc_add"
        $ggurl = "http://www.google.com/webhp"

    condition:
        3 of them
}
