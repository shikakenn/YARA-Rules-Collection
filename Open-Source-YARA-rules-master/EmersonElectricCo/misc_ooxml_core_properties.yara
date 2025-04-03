rule misc_ooxml_core_properties
{
    meta:
        id = "1K2YZCpha94nZl2vukxqaw"
        fingerprint = "v1_sha256_d5366756fcdbe5009bf13df22f3ef9e52c9c0d3b90d0a04fbc57a126e8ed1947"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20150505"
        desc = "Identify meta xml content within OOXML documents"

   strings:
      $xml = "<?xml version="
      $core = "<cp:coreProperties xmlns:cp"

   condition:
      $xml at 0 and $core
}

