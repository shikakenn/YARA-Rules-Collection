import "pe"

rule misc_pe_signature
{
    meta:
        id = "5rsTo09vNNn4u7eUB7mzDS"
        fingerprint = "v1_sha256_d5a97b74c53a8b0e4f9705c62fb00cc0669d960872710828005bb392e28fe76e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20150911"
        desc = "Triggers if an authenticode signature is present within a PE file (if the PE is signed for example)"

   condition:
      pe.number_of_signatures > 0
}
