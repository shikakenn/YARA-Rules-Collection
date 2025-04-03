rule unpacked_shiva_ransomware {

    meta:
        id = "2kyUfN8WibOsuhuSsd9set"
        fingerprint = "v1_sha256_8a6a1d9f3b75617d8f07489ecf2867f90ddcf9fbe1db1e7c0f5c26833f88be3f"
        version = "1.0"
        date = "2018-09-05"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect an unpacked sample of Shiva ransomware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://twitter.com/malwrhunterteam/status/1037424962569732096"
        hash = "299bebcb18e218254960ef96c2e65a4dc1945dcdfe9fc68550022f99a474f56d"
        rule_version = "v1"
        malware_family = "Ransom:W32/Shiva"
        actor_group = "Unknown"

   strings:

      $s1 = "c:\\Users\\sys\\Desktop\\v 0.5\\Shiva\\Shiva\\obj\\Debug\\shiva.pdb" fullword ascii
      $s2 = "This email will be as confirmation you are ready to pay for decryption key." fullword wide
      $s3 = "Your important files are now encrypted due to a security problem with your PC!" fullword wide
      $s4 = "write.php?info=" fullword wide
      $s5 = " * Do not try to decrypt your data using third party software, it may cause permanent data loss." fullword wide
      $s6 = " * Do not rename encrypted files." fullword wide
      $s7 = ".compositiontemplate" fullword wide
      $s8 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." fullword wide
      $s9 = "\\READ_IT.txt" fullword wide
      $s10 = ".lastlogin" fullword wide
      $s11 = ".logonxp" fullword wide
      $s12 = " * Decryption of your files with the help of third parties may cause increased price" fullword wide
      $s13 = "After payment we will send you the decryption tool that will decrypt all your files." fullword wide
   
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 800KB ) and
      all of them 
}
