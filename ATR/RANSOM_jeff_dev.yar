rule jeff_dev_ransomware {

    meta:
        id = "7UZBxdkTrfH9XWOTYWWyDR"
        fingerprint = "v1_sha256_58a408f4e1781540e4abdb87b85b94c1f0ea49b40bf241d6d074bc2162ac2032"
        version = "1.0"
        date = "2018-08-26"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Jeff Dev Ransomware"
        category = "INFO"
        reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
        hash = "386d4617046790f7f1fcf37505be4ffe51d165ba7cbd42324aed723288ca7e0a"
        rule_version = "v1"
        malware_family = "Ransom:W32/Jeff"
        actor_group = "Unknown"

   strings:

      $s1 = "C:\\Users\\Umut\\Desktop\\takemeon" fullword wide
      $s2 = "C:\\Users\\Umut\\Desktop\\" fullword ascii
      $s3 = "PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER" fullword wide
      $s4 = "WHAT YOU DO TO MY COMPUTER??!??!!!" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 5000KB ) and
      all of them
}
