rule ft_rar
{
    meta:
        id = "2PuuIFaSfhbQMEK5ctVwo9"
        fingerprint = "v1_sha256_f15820206213272347a2c9c28c35d9dfabdd79c4dcc5b09ae85ccc6764a5fac0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "James Ferrer"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20150107"
        desc = "File type signature for basic .rar files"

   strings:
      $Rar = {52 61 72 21 1A 07} 
      
   condition:

      $Rar at 0
}
