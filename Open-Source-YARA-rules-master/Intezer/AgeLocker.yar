rule AgeLocker
{
    meta:
        id = "xlqW2iD487wzxS1fxzKIw"
        fingerprint = "v1_sha256_0db7db0440d0a03437672d3a64462a6619dde18f35f36c4fce650a20bdba325e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
        $a0 = "agelocker.go"
        $a1 = "filippo.io/age/age.go"
        $b0 = "main.encrypt"
        $b2 = "main.stringInSlice"
        $b3 = "main.create_message"
        $b4 = "main.fileExists"


    condition:
        any of ($a*) and any of ($b*)
}
