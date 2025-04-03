rule ft_cab
{
    meta:
        id = "4g2eKPIxnBCSVZXR5SUV96"
        fingerprint = "v1_sha256_d746919e05248307a33d2b1192f17d49627482b14279c796534cbac84102d786"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20150723"
        desc = "File magic for CABs (Microsoft Cabinet Files)"

   strings:
      $cab = { 4D 53 43 46 }

   condition:
      $cab at 0
}
