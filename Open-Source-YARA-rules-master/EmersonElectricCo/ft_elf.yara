rule ft_elf
{
    meta:
        id = "1Zvd2hKYT5zsI1YRcol9Ou"
        fingerprint = "v1_sha256_880839389016fb037c94dcd0ceb0203c8f56f2a3ac8a258b26a45a049d2d8238"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20160121"
        desc = "File magic for ELF files"

   strings:
      $magic = { 7f 45 4c 46 }

   condition:
      $magic at 0 
}
