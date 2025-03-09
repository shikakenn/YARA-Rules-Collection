import "pe"
rule HermeticWiper_Certificate {
    meta:
        id = "JtJKtqAoqguWiUCuOJn29"
        fingerprint = "v1_sha256_b15d551fd7f7939062335a97aa652d11bd38b1c49cc77610d3c45547e4145ee6"
        version = "1.0"
        date = "2022-02-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@X0RC1SM"
        description = "Detects a certificate used in HermeticWiper Attack"
        category = "INFO"
        hash = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
        malware = "HermeticWiper"

   condition:
      uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_signatures) : (pe.signatures[i].serial == "0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec")
}
