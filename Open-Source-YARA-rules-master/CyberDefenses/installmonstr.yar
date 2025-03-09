rule installmonstr {
    meta:
        id = "3hHlHcN5mbhdbizIK7p9DM"
        fingerprint = "v1_sha256_0588d23a35e2917d182b4e6ed96efdc658fa327c17abc1972b223677122d6c1a"
        version = "1.0"
        date = "2017/01/25"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Monty St John"
        description = "adware, trojan, riskware"
        category = "INFO"
        company = "Cyberdefenses, inc."
        hash1 = "000be3b9991eaf28b3794d96ce08e883"
        hash2 = "1c21a4b1151921398b2c2fe9ea9892f8"
        hash3 = "be6eb42ea9e789d2a4425f61155f4664"
        hash4 = "001dd4fdd6973f4e6cb9d11bd9ba7eb3"

strings:
    $a = "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; URL=%0:s\">"
    $b = "%s<input type=\"hidden\" name=\"%s\" value=\"%s\">%s"
    $c = "GoIdHTTPWork"
    $d = "sslvSSLv2sslvSSLv23sslvSSLv3sslvTLSv1"
    $e = "sslvSSLv23	sslvSSLv3	sslvTLSv1"
    $f = "AES:ALL:!aNULL:!eNULL:+RC4:@STRENGTH"

condition:
  5 of them 
}
