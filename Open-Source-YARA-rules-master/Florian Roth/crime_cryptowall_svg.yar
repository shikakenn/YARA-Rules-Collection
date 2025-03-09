
rule SVG_LoadURL {
    meta:
        id = "1CF8KEJimd2MBkZx3qKgWV"
        fingerprint = "v1_sha256_d9e40694e2d0099495289a2074e266bace9b0d9d776391020a1527eaabd2a395"
        version = "1.0"
        score = 50
        date = "2015-05-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
        category = "INFO"
        reference = "http://goo.gl/psjCCc"
        hash1 = "ac8ef9df208f624be9c7e7804de55318"
        hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
        hash3 = "7e2be5cc785ef7711282cea8980b9fee"
        hash4 = "4e2c6f6b3907ec882596024e55c2b58b"

    strings:
        $s1 = "</svg>" nocase
        $s2 = "<script>" nocase
        $s3 = "location.href='http" nocase
    condition:
        all of ($s*) and filesize < 600
}

        
        
