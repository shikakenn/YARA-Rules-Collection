rule screenlocker_acroware {

    meta:
        id = "4msTwGV3RPCYnhQC8g7Td0"
        fingerprint = "v1_sha256_582f3544cf1f8066b1e9ac04c3a4cc9f0ba96804ca53bc3746b433df9c33e0a1"
        version = "1.0"
        date = "2018-08-28"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the ScreenLocker Acroware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
        hash = "f9efcfc5328e6502cbbbff752a940ac221e437d8732052fc265618f6a6ad72ae"
        rule_version = "v1"
        malware_family = "Ransom:W32/Acroware"
        actor_group = "Unknown"

   strings:

      $s1 = "C:\\Users\\patri\\Documents\\Visual Studio 2015\\Projects\\Advanced Ransi\\Advanced Ransi\\obj\\Debug\\Advanced Ransi.pdb" fullword ascii
      $s2 = "All your Personal Data got encrypted and the decryption key is stored on a hidden" fullword ascii
      $s3 = "alphaoil@mail2tor.com any try of removing this Ransomware will result in an instantly " fullword ascii
      $s4 = "HKEY_CURRENT_USER\\SoftwareE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
      $s5 = "webserver, after 72 hours thedecryption key will get removed and your personal" fullword ascii
      
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 2000KB ) and
      all of them
}
