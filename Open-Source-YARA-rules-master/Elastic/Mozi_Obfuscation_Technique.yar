rule Mozi_Obfuscation_Technique
{
    meta:
        id = "2vEh6ooVgWSB47WbsKnCAQ"
        fingerprint = "v1_sha256_405ab0252b2a145b681f3a4073e8dd04123638fdd96ad6c0e80bec1ddb69f553"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security, Lars Wallenborn (@larsborn)"
        description = "Detects obfuscation technique used by Mozi botnet."
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/collecting-and-operationalizing-threat-data-from-the-mozi-botnet"

  strings:
    $a = { 55 50 58 21
           [4]
           00 00 00 00
           00 00 00 00
           00 00 00 00 }
  condition:
    all of them
}
