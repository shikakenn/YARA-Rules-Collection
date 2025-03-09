rule hikit2
{
    meta:
        id = "1HALRLQ6SaGWYDGZ4e4a1b"
        fingerprint = "v1_sha256_8bcfbfcf83c5b2987a7bb02dbce7f24ff0b06015a3a0f644325c7964ce067723"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Novetta"
        Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

    strings:
        $magic1 = {8C 24 24 43 2B 2B 22 13 13 13 00}
        $magic2 = {8A 25 25 42 28 28 20 1C 1C 1C 15 15 15 0E 0E 0E 05 05 05 00}

    condition:
        $magic1 and $magic2
}
