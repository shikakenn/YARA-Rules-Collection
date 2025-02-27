rule apt_manitsme_trojan {
  
    meta:
        id = "3fbXNVld2V3qn4YBFgPj29"
        fingerprint = "v1_sha256_584053145249a930d3eae5e291d3553c57fa427dbecac9f04e7c0169f153b7af"
        version = "1.0"
        date = "2013-03-08"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Manitsme trojan"
        category = "INFO"
        reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
        hash = "c1c0ea096ec4d36c1312171de2a9ebe258c588528a20dbb06a7e3cf97bf1e197"
        rule_version = "v1"
        malware_family = "Trojan:W32/Manitsme"
        actor_group = "Unknown"

   strings:
  
      $s1 = "SvcMain.dll" fullword ascii
      $s2 = "rj.soft.misecure.com" fullword ascii
      $s3 = "d:\\rouji\\SvcMain.pdb" fullword ascii
      $s4 = "constructor or from DllMain." fullword ascii
      $s5 = "Open File Error" fullword ascii
      $s6 = "nRet == SOCKET_ERROR" fullword ascii
      $s7 = "Oh,shit" fullword ascii
      $s8 = "Paraing" fullword ascii
      $s9 = "Hallelujah" fullword ascii
      $s10 = "ComSpec" fullword ascii /* Goodware String - occured 11 times */
      $s11 = "ServiceMain" fullword ascii /* Goodware String - occured 486 times */
      $s12 = "SendTo(s,(char *)&sztop,sizeof(sztop),FILETYPE) == ERRTYPE" fullword ascii
  
   condition:

      uint16(0) == 0x5a4d and 
      filesize < 200KB and 
      all of them
}
