rule UNC3524_sha1

{

    meta:
        id = "54LJsH5a01ay4tJhCbTZYO"
        fingerprint = "v1_sha256_23d1b3feb04cc6e9e2e9cdf8e7440af4cd5842b822153fb7200386facc5c00c6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"
        date_created = "2022-01-19"
        date_modified = "2022-01-19"

   strings:

        $h1 = { DD E5 D5 97 20 53 27 BF F0 A2 BA CD 96 35 9A AD 1C 75 EB 47 }

    condition:

        uint32be(0) == 0x7F454C46 and filesize < 10MB and all of them

}


