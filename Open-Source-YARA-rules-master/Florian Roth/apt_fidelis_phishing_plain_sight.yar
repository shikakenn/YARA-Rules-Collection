
rule Fidelis_Advisory_Purchase_Order_pps {
    meta:
        id = "2rB7Rh6S9BtKyYgYsiny7y"
        fingerprint = "v1_sha256_45cfee6413accff36a39ced861a29c611d6efe24e1ca87f17467106f8565642b"
        version = "1.0"
        date = "2015-06-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a string found in a malicious document named Purchase_Order.pps"
        category = "INFO"
        reference = "http://goo.gl/ZjJyti"

    strings:
        $s0 = "Users\\Gozie\\Desktop\\Purchase-Order.gif" ascii
    condition:
        all of them
}

rule Fidelis_Advisory_cedt370 {
    meta:
        id = "6ybjNH9HQlLpVr8JLJ8xVr"
        fingerprint = "v1_sha256_1070d3c63a7091c0982e67134f9dc3cd790bb0b5c2ac08f3a00e3b97ef53d64b"
        version = "1.0"
        date = "2015-06-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a string found in memory of malware cedt370r(3).exe"
        category = "INFO"
        reference = "http://goo.gl/ZjJyti"

    strings:
        $s0 = "PO.exe" ascii fullword
        $s1 = "Important.exe" ascii fullword
        $s2 = "&username=" ascii fullword
        $s3 = "Browsers.txt" ascii fullword
    condition:
        all of them
}
