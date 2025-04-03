
rule Office_AutoOpen_Macro {
    meta:
        id = "9OhySrTljOpKYHELnrzHX"
        fingerprint = "v1_sha256_23c834828e7a9ea966e5d7247881bbbf9180b8f08297e36cd36d2ba5f621c70d"
        version = "1.0"
        score = 40
        date = "2015-05-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
        category = "INFO"
        hash1 = "4d00695d5011427efc33c9722c61ced2"
        hash2 = "63f6b20cb39630b13c14823874bd3743"
        hash3 = "66e67c2d84af85a569a04042141164e6"
        hash4 = "a3035716fe9173703941876c2bde9d98"
        hash5 = "7c06cab49b9332962625b16f15708345"
        hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
        hash7 = "25285b8fe2c41bd54079c92c1b761381"

    strings:
        $s1 = "AutoOpen" ascii fullword
        $s2 = "Macros" wide fullword
    condition:
        (
            uint32be(0) == 0xd0cf11e0 or 	// DOC, PPT, XLS
            uint32be(0) == 0x504b0304		// DOCX, PPTX, XLSX (PKZIP)
        )
        and all of ($s*) and filesize < 300000
}

rule Office_as_MHTML {
    meta:
        id = "Ww59qi0kuaY2wxiv7zPWp"
        fingerprint = "v1_sha256_d5836a9c627e2e6833ea9e27526c76c00fc1fcf1fca8ea10777aa6f4bcc25053"
        version = "1.0"
        score = 40
        date = "2015-05-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an Microsoft Office saved as a MHTML file (false positives are possible but rare; many matches on CVE-2012-0158)"
        category = "INFO"
        reference = "https://www.trustwave.com/Resources/SpiderLabs-Blog/Malicious-Macros-Evades-Detection-by-Using-Unusual-File-Format/"
        hash1 = "8391d6992bc037a891d2e91fd474b91bd821fe6cb9cfc62d1ee9a013b18eca80"
        hash2 = "1ff3573fe995f35e70597c75d163bdd9bed86e2238867b328ccca2a5906c4eef"
        hash3 = "d44a76120a505a9655f0224c6660932120ef2b72fee4642bab62ede136499590"
        hash4 = "5b8019d339907ab948a413d2be4bdb3e5fdabb320f5edc726dc60b4c70e74c84"

    strings:
        $s1 = "Content-Transfer-Encoding: base64" ascii fullword
        $s2 = "Content-Type: application/x-mso" ascii fullword

        $x1 = "QWN0aXZlTWltZQA" ascii 	// Base64 encoded 'ActiveMime'
        $x2 = "0M8R4KGxGuE" ascii 		// Base64 encoded office header D0CF11E0A1B11AE1..
    condition:
        uint32be(0) == 0x4d494d45 // "MIME" header
        and all of ($s*) and 1 of ($x*)
}
