rule Artifact_ORION_aPlib
{
    meta:
        id = "3DUDU9H7m5cVVTHSpkbDQr"
        fingerprint = "v1_sha256_2aa02dc7e50b791aad479654f70781bbd2cae2079d09ce5718ce87120d0d5483"
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
        Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

    strings:
        $a1 = "aPLib v"
        $a2 = "the smaller the better :)"
        $a3 = "Joergen Ibsen"
    condition:
        all of them

}
