rule pico_ransomware {
   
    meta:
        id = "60j5e4tIof5d9D8f9voOUt"
        fingerprint = "v1_sha256_bb15e66504f393bcb4b173cb2a4ec65aa13110060f7fb70282330b5f6d72f5ed"
        version = "1.0"
        date = "2018-08-30"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Pico Ransomware"
        category = "INFO"
        reference = "https://twitter.com/siri_urz/status/1035138577934557184"
        hash = "cc4a9e410d38a29d0b6c19e79223b270e3a1c326b79c03bec73840b37778bc06"
        rule_version = "v1"
        malware_family = "Ransom:W32/Pico"
        actor_group = "Unknown"

   strings:

      $s1 = "C:\\Users\\rikfe\\Desktop\\Ransomware\\ThanatosSource\\Release\\Ransomware.pdb" fullword ascii
      $s2 = "\\Downloads\\README.txt" fullword ascii
      $s3 = "\\Music\\README.txt" fullword ascii
      $s4 = "\\Videos\\README.txt" fullword ascii
      $s5 = "\\Pictures\\README.txt" fullword ascii
      $s6 = "\\Desktop\\README.txt" fullword ascii
      $s7 = "\\Documents\\README.txt" fullword ascii
      $s8 = "/c taskkill /im " fullword ascii
      $s9 = "\\AppData\\Roaming\\" fullword ascii
      $s10 = "gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1" fullword wide
      $s11 = "AppData\\Roaming" fullword ascii
      $s12 = "\\Downloads" fullword ascii
      $s13 = "operator co_await" fullword ascii
   
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 700KB ) and
      all of them
}
