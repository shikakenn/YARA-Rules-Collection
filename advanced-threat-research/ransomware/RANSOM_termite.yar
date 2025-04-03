rule termite_ransomware {

    meta:
        id = "3uy4LkHPEfVkbMZrBy3xTa"
        fingerprint = "v1_sha256_e5c01e8377957fa25cf6c2031c2680e802b0082a36f50b97b4e488c5bf40e968"
        version = "1.0"
        date = "2018-08-28"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee ATR Team"
        description = "Rule to detect the Termite Ransomware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
        hash = "021ca4692d3a721af510f294326a31780d6f8fcd9be2046d1c2a0902a7d58133"
        rule_version = "v1"
        malware_family = "Ransom:W32/Termite"
        actor_group = "Unknown"

   strings:
      
      $s1 = "C:\\Windows\\SysNative\\mswsock.dll" fullword ascii
      $s2 = "C:\\Windows\\SysWOW64\\mswsock.dll" fullword ascii
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Termite.exe" fullword ascii
      $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Payment.exe" fullword ascii
      $s5 = "C:\\Windows\\Termite.exe" fullword ascii
      $s6 = "\\Shell\\Open\\Command\\" fullword ascii
      $s7 = "t314.520@qq.com" fullword ascii
      $s8 = "(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
      
   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 6000KB ) and
      all of them 
}
