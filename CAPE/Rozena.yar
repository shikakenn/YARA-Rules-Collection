rule Rozena
{
    meta:
        id = "1n4OKYg61FhI9iPPYQRYsO"
        fingerprint = "v1_sha256_c415a8108b58a125a604031bb8d73b58a8aae5429b5b765e35fa8a4add9cd135"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        cape_type = "Rozena Payload"

    strings:
        $ip_port = {FF D5 6A 0A 68 [4] 68 [4] 89 E6 50 50 50 50 40 50 40 50 68 [4] FF D5}
        $socket = {6A 00 6A 04 56 57 68 [4] FF D5 [0-5] 8B 36 6A 40 68 00 10 00 00 56 6A 00 68}
    condition:
        all of them
}
