rule ft_zip
{
    meta:
        id = "6LvzOAy9RDcl0TXoU60C0E"
        fingerprint = "v1_sha256_9da27579ab6522d0db36fc01b5f72440fe5c5781ba834f6b3cf39cf0d3888701"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20141217"
        desc = "File type signature for basic ZIP files."

   strings:
      $pk = { 50 4B 03 04 }

   condition:
      $pk at 0
}
