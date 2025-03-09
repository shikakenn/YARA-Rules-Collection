import "pe"

rule RomeoEcho
{
    meta:
        id = "4Wj5vcsTnSIqAHhvPr6EGl"
        fingerprint = "v1_sha256_d9556d7f20c0469b863f7dd2e9777f523650cc3daaaa76c1bb4776ce92a625e6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $ = "%s %-20s %10lu %s"
        $ = "_quit"
        $ = "_exe"
        $ = "_put"
        $ = "_get"

    condition:
        all of them
}
