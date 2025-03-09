rule xtremrat : rat
{
    meta:
        id = "73SCxBPOy9tOQUohiX0EKq"
        fingerprint = "v1_sha256_56a079bcd12668a9f810bbe5b85b8816e44444022b32b06b02af56f1af5b0178"
        version = "1.0"
        date = "2012-07-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Xtrem RAT v3.5"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "XTREME" wide
        $b = "XTREMEBINDER" wide
        $c = "STARTSERVERBUFFER" wide
        $d = "SOFTWARE\\XtremeRAT" wide
        $e = "XTREMEUPDATE" wide
        $f = "XtremeKeylogger" wide
        $g = "myversion|3.5" wide
        $h = "xtreme rat" wide nocase
    condition:
        2 of them
}
