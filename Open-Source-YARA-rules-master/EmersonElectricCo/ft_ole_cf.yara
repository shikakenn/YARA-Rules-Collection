rule ft_ole_cf
{
    meta:
        id = "4jYFujZM7I05Icsh18oQh6"
        fingerprint = "v1_sha256_4bce59ef15341e63bbd1fd1f12b43acdf2f20b010f180097e702911b2fb9648c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20141202"
        desc = "Detect file magic indicative of OLE CF files (commonly used by early versions of MS Office)."

   strings:
      $magic = { D0 CF 11 E0 A1 B1 1A E1 }

   condition:
      $magic at 0
}
