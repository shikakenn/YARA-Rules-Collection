rule DeviceGuard_WDS_Evasion {
    meta:
        id = "5Qh9wFpOynZPK7HBqwWHhQ"
        fingerprint = "v1_sha256_71f4633a04916f32617b1b1ef00147a419c0550b7e33c4e9cf8c7e8a08e3d5f9"
        version = "1.0"
        score = 80
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects WDS file used to circumvent Device Guard"
        category = "INFO"
        reference = "http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html"

   strings:
      $s1 = "r @$ip=@$t0" ascii fullword
      $s2 = ";eb @$t0+" ascii
      $s3 = ".foreach /pS" ascii fullword
   condition:
      filesize < 50KB and all of them
}
