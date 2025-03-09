rule xtreme_rat : Trojan
{
    meta:
        id = "2lVzDWHzkcHhC88M3ROr5U"
        fingerprint = "v1_sha256_fa7e3f735a77f0254c8f388458b5b7ebaf9ae8ba12603041ef410f0010dbc89e"
        version = "1.0"
        date = "23/02/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Xtreme RAT"
        category = "INFO"

    strings:
        $signature1={58 00 54 00 52 00 45 00 4D 00 45} /*X.T.R.E.M.E*/
        
    condition:
        $signature1
}
