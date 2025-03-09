rule android_tempting_cedar_spyware
{
    meta:
        id = "3os2Jo42fp6AKmRwKnqtql"
        fingerprint = "v1_sha256_d91907557fd0ab534da5ca92cb66cebd245a23fc2032f2b25eaadb97c4fc7203"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "@X0RC1SM"
        Date = "2018-03-06"
        Reference = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"

    strings:
          $PK_HEADER = {50 4B 03 04}
           $MANIFEST = "META-INF/MANIFEST.MF"
          $DEX_FILE = "classes.dex"
          $string = "rsdroid.crt"
    
    condition:
        $PK_HEADER in (0..4) and $MANIFEST and $DEX_FILE and any of ($string*)
}
