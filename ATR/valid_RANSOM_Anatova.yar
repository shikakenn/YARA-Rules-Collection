rule anatova_ransomware {

    meta:
        id = "4oWwnGSWMhxUT27KWXdEZ3"
        fingerprint = "v1_sha256_4fce15ad0ef2d3cb39f6092677f117308f847815cb2a5a491290a1f9d09776df"
        version = "1.0"
        date = "2019-01-22"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Anatova Ransomware"
        category = "INFO"
        reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/happy-new-year-2019-anatova-is-here/"
        hash = "97fb79ca6fc5d24384bf5ae3d01bf5e77f1d2c0716968681e79c097a7d95fb93"
        rule_version = "v1"
        malware_family = "Ransom:W32/Anatova"
        actor_group = "Unknown"

   strings:

      $regex = /anatova[0-9]@tutanota.com/
        
    condition:

        uint16(0) == 0x5a4d and
        filesize < 2000KB and
        $regex
}
