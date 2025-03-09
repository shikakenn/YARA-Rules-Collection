rule lost_door : Trojan
{
    meta:
        id = "5bC4YXzbBqeV75k5nowr1s"
        fingerprint = "v1_sha256_632a3932ab5d7086c11b03bc80347c37ef1f967b7d070f7483ba74d17d356175"
        version = "1.0"
        date = "23/02/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Lost Door"
        category = "INFO"

    strings:
        $signature1={45 44 49 54 5F 53 45 52 56 45 52} /*EDIT_SERVER*/
        
    condition:
        $signature1
}
