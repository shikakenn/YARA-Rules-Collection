rule ft_gzip
{
    meta:
        id = "1LbI3hoJmvs1ePyOWvpsJe"
        fingerprint = "v1_sha256_2b8733a586244254a02e1f1486152c93b0d5505db804818027cc12bccd7bd260"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20151116"
        desc = "Trigger on magic of GZip compressed files"

   strings:
      $magic = { 1f 8b 08 }

   condition:
      $magic at 0
}
