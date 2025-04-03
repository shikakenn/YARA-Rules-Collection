rule YahLover : Worm
{
    meta:
        id = "76HyedQmboiooX0zVI9aCJ"
        fingerprint = "v1_sha256_11727a467096f6614e69c454e9ac4b5a56229be83fb7103386a2a8be0c180b7f"
        version = "1.0"
        date = "10/06/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "YahLover"
        category = "INFO"

    strings:
        $signature1={42 00 49 00 54 00 52 00 4F 00 54 00 41 00 54 00 45 00 00 00 42 00 49 00 54 00 53 00 48 00 49 00 46 00 54 00 00 00 00 00 42 00 49 00 54 00 58 00 4F 00 52}
        
    condition:
        $signature1
}
