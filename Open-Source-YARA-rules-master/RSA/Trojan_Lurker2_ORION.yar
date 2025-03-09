rule Trojan_Lurker2_ORION
{
    meta:
        id = "1YqU3EZJx9xB8i1BFRrw7e"
        fingerprint = "v1_sha256_1dbe63aae14e5b54362e8a102dec51d99ffb8f12a839ba619532cf8fdabde89c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "HB"
        Date = "30 Sep 2013"
        Project = "Orion"
        Filename = "ntmrsvc.dll"
        Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

    strings:
        $b1 = {636D642E657865004C55524B}
        $b2 = {45525F52414353004C55524B25735F534D5F2573}
        $b3 = {4C55524B4552524143535F524D5F2573}
        $a1 = "01234567890123456789eric0123456789012345678karen"

    condition:
        any of them
}
