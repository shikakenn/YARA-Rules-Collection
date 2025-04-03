rule karkoff_dnspionaje {
   
    meta:
        id = "2D3pbQH9JEWq9fzTcELF9O"
        fingerprint = "v1_sha256_79dd0087f1197cb1b2cd98416302363951479ba5ebf82289768585b56ed21c3a"
        version = "1.0"
        date = "2019-04-23"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Karkoff malware"
        category = "MALWARE"
        malware_type = "BACKDOOR"
        actor_type = "APT"
        reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
        hash = "5b102bf4d997688268bab45336cead7cdf188eb0d6355764e53b4f62e1cdf30c"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Karkoff"
        actor_group = "Unknown"

   strings:
   
      $s1 = "DropperBackdoor.Newtonsoft.Json.dll" fullword wide
      $s2 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword wide
      $s3 = "DropperBackdoor.exe" fullword wide
      $s4 = "get_ProcessExtensionDataNames" fullword ascii
      $s5 = "get_ProcessDictionaryKeys" fullword ascii
      $s6 = "https://www.newtonsoft.com/json 0" fullword ascii
      
   condition:
   
      uint16(0) == 0x5a4d and
      filesize < 1000KB 
      and all of them
}
