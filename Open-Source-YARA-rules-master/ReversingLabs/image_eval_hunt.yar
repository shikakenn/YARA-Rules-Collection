rule image_eval_hunt
{
    meta:
        id = "17jGDbAKDdh4CyZYlxfFo0"
        fingerprint = "v1_sha256_7d77eefb57737dfbcdaade8e981d0e3657304179da1eb80a0bb189cc7bc58a11"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "ReversingLabs"
        description = "NA"
        category = "INFO"
        reference = "https://blog.reversinglabs.com/blog/malware-in-images"

   strings:
      $png = {89 50 4E 47}
      $jpeg = {FF D8 FF}
      $gif = "GIF"
      $eval = "eval("
   condition:
      (($png at 0) or ($jpeg at 0) or ($gif at 0)) and $eval
}
