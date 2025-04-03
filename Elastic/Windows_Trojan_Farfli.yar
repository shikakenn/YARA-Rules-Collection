rule Windows_Trojan_Farfli_85d1bcc9 {
    meta:
        id = "47jzyMVFEDer8ZDYac5RqL"
        fingerprint = "v1_sha256_746eb5a2583077189d82d1a96b499ff383f31220845bd8a6df5b7a7ceb11e6fb"
        version = "1.0"
        date = "2022-02-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Farfli"
        reference_sample = "e3e9ea1b547cc235e6f1a78b4ca620c69a54209f84c7de9af17eb5b02e9b58c3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { AB 66 AB C6 45 D4 25 C6 45 D5 73 C6 45 D6 5C C6 45 D7 25 C6 45 }
    condition:
        all of them
}

