rule ft_exe
{
    meta:
        id = "2wwn8HaRkc2GqTiYdOWaXu"
        fingerprint = "v1_sha256_894ab8e2e4d0f456bf9da53dacd9e0c02aebe9c308bc16f0de5bf095b12b9be3"
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
        desc = "Simple signature to trigger on PE files."

   strings:
      $mz = "MZ"

   condition:
      $mz at 0
}
