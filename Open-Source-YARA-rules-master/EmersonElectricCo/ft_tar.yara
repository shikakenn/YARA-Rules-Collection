rule ft_tar
{
    meta:
        id = "5U9F9nEVXPe4CEHJybdTC3"
        fingerprint = "v1_sha256_2d4543d5b9378283dae7e7f6657fcc22200869f092632136f4fd87db720c6150"
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
        desc = "Signature to detect on TAR archive files"

   strings:
      $magic = { 75 73 74 61 72 }

   condition:
      $magic at 257
}
