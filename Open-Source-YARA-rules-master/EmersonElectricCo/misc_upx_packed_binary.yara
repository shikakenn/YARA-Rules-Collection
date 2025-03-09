import "pe"

rule misc_upx_packed_binary
{
    meta:
        id = "1DLnzcNirJimd4ZFiXR4WZ"
        fingerprint = "v1_sha256_ee9654903acdd1db5efa0e824ab17c98694eccb3f4f0b697808d6715657a5766"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20150520"
        desc = "Detect section names indicative of UPX packed PE files"

   condition:
      (pe.sections[0].name == "UPX0" and pe.sections[1].name == "UPX1")
}
