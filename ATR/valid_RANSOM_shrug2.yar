rule shrug2_ransomware {

    meta:
        id = "1jCxjfjHTfqbx8nrpbH01q"
        fingerprint = "v1_sha256_8c817b7fc4a0eada08b3d298c94b99a85c4e5a49a49d1c3fabdb0c6bbf56676b"
        version = "1.0"
        date = "2018-07-12"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "McAfee ATR Team"
        description = "Rule to detect the Shrug Ransomware"
        category = "INFO"
        reference = "https://blogs.quickheal.com/new-net-ransomware-shrug2/"
        hash = "c89833833885bafdcfa1c6ee84d7dbcf2389b85d7282a6d5747da22138bd5c59"
        rule_version = "v1"
        malware_family = "Ransom:W32/Shrug"
        actor_group = "Unknown"

   strings:

      $s1 = "C:\\Users\\Gamer\\Desktop\\Shrug2\\ShrugTwo\\ShrugTwo\\obj\\Debug\\ShrugTwo.pdb" fullword ascii
      $s2 = "http://tempacc11vl.000webhostapp.com/" fullword wide
      $s3 = "Shortcut for @ShrugDecryptor@.exe" fullword wide
      $s4 = "C:\\Users\\" fullword wide
      $s5 = "http://clients3.google.com/generate_204" fullword wide
      $s6 = "\\Desktop\\@ShrugDecryptor@.lnk" fullword wide
   
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 2000KB ) and
      all of them 
}
