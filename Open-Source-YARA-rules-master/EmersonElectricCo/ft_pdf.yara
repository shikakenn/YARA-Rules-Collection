rule ft_pdf
{
    meta:
        id = "97w2swt744hxOVHrZh79D"
        fingerprint = "v1_sha256_a4c0803c435b16436f7272ad1a5620809a6c43dcc8a798b3655c409cd23d87ab"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20141230"
        desc = "Signature to trigger on PDF file magic."

   strings:
      $pdf = "%PDF"

   condition:
      $pdf in (0 .. 1024)
}
