rule DarkComet : rat
{
    meta:
        id = "795dOVWXHkAmYI4KsXV8Lg"
        fingerprint = "v1_sha256_b0548831f9ac5f27709d6a4e757977dcfb7c73eda3dbb0bfa122c714e2ad3a2c"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "DarkComet"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "#BEGIN DARKCOMET DATA --"
        $b = "#EOF DARKCOMET DATA --"
        $c = "DC_MUTEX-"
        $k1 = "#KCMDDC5#-890"
        $k2 = "#KCMDDC51#-890"

    condition:
        any of them
}
