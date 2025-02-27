rule Robbinhood_ransomware {

    meta:
        id = "74lBEGSoQf83qERAki9E54"
        fingerprint = "v1_sha256_19a1b7d92bc49dee6da3fb4c053b118e6475aeca43e891d46470c2c09c148038"
        version = "1.0"
        date = "2019-05-10"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Christiaan Beek | McAfee ATR"
        description = "Robbinhood GoLang ransowmare"
        category = "INFO"
        hash = "9977ba861016edef0c3fb38517a8a68dbf7d3c17de07266cfa515b750b0d249e"
        rule_version = "v1"
        malware_family = "Ransom:W32/Robbinhood"
        actor_group = "Unknown"

   strings:

      $s1 = ".enc_robbinhood" nocase
      $s2 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s3 = "pub.key" nocase
      $s4 = "main.EnableShadowFucks" nocase
      $s5 = "main.EnableRecoveryFCK" nocase
      $s6 = "main.EnableLogLaunders" nocase
      $s7 = "main.EnableServiceFuck" nocase
     

      $op0 = { 8d 05 2d 98 51 00 89 44 24 30 c7 44 24 34 1d }
      $op1 = { 8b 5f 10 01 c3 8b 47 04 81 c3 b5 bc b0 34 8b 4f }
      $op2 = { 0f b6 34 18 8d 7e d0 97 80 f8 09 97 77 39 81 fd }

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 3000KB and
      ( 1 of ($s*) ) and
      all of ($op*)) or 
      ( all of them )
}

