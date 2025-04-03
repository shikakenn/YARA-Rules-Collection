rule trickbot_maldoc_embedded_dll_september_2020 {
    meta:
        id = "62LunpCu7JjY6cJs8uV4KB"
        fingerprint = "v1_sha256_3f2c544542dd59b1afb1c5c49dd613af5fc2278223c5e2006e285c411340a2a4"
        version = "1.0"
        date = "2020-10-03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "HP-Bromium Threat Research"
        description = "NA"
        category = "INFO"
        reference = "https://threatresearch.ext.hp.com/detecting-a-stealthy-trickbot-campaign/"

    strings:
        $magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "EncryptedPackage" wide
        $s2 = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}" wide
        $s3 = { FF FF FF FF FF FF FF FF FF FF ( 90 90 | 10 10 | E2 E2 | 17 17 ) FF FF FF FF FF FF FF FF FF FF }

    condition:
        $magic at 0 and
        all of ($s*) and
        (filesize > 500KB and filesize < 1000KB)
}
