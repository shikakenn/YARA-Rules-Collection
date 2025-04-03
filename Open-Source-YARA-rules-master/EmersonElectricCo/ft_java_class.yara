rule ft_java_class
{
    meta:
        id = "7RvdmuYTmAOTyptox0xo0Z"
        fingerprint = "v1_sha256_3b8e2e8382be91c781e4fa7f3379c33d639db701648392c27efa6b28cbd6ab9b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20160126"
        desc = "File magic for detecting a Java bytecode file."

   strings:
      $class = { CA FE BA BE }

   condition:
      $class at 0
}
