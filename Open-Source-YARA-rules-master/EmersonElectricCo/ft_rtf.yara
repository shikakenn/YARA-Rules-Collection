rule ft_rtf
{
    meta:
        id = "6qDd8VsmJ90GK9mnSrYIZW"
        fingerprint = "v1_sha256_b94b5cf021bd785843c4ee04dde3e38eff48e1e80d0419a2c201272d0a4ec9b0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20141204"
        desc = "Hit on RTF files by triggering on RTF file magic"

   strings:
      $rtf = { 7B 5C 72 74 66 }

   condition:
      $rtf at 0
}
