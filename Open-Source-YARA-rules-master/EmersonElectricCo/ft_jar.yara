rule ft_jar
{
    meta:
        id = "7XuosWR8DiKF2rfeCqghjs"
        fingerprint = "v1_sha256_60267e67d371fb27807695e9d0c353f524e567d3e03f37ca5d2b931abbbf6173"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20150810"
        desc = "Signature to detect JAR files"

   strings:
      $pk_header = { 50 4B 03 04 }
      $jar = "META-INF/MANIFEST.MF"

   condition:
      $pk_header at 0 and $jar
}
