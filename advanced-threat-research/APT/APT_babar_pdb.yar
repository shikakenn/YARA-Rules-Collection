rule apt_babar_malware {

    meta:
        id = "5pyNkcUyMrQCBPxETPBNLA"
        fingerprint = "v1_sha256_02acef92691caed4573b609c111302427b9c27c5ef93f9199c52d75cb13e8615"
        version = "1.0"
        date = "2015-02-18"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Babar malware"
        category = "MALWARE"
        malware_type = "BACKDOOR"
        actor_type = "CRIMEWARE"
        reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
        hash = "c72a055b677cd9e5e2b2dcbba520425d023d906e6ee609b79c643d9034938ebf"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Babar"
        actor_group = "Unknown"

   strings:

      $s1 = "c:\\Documents and Settings\\admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper Release\\Release.pdb" fullword ascii
      $s2 = "%COMMON_APPDATA%" fullword ascii
      $s3 = "%%WINDIR%%\\%s\\%s" fullword ascii
      $s4 = "/s /n %s \"%s\"" fullword ascii
      $s5 = "/c start /wait " fullword ascii
      $s6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
      $s7 = "constructor or from DllMain." fullword ascii
      $s8 = "ComSpec" fullword ascii 
      $s9 = "APPDATA" fullword ascii 
      $s10 = "WINDIR" fullword ascii 
      $s11 = "USERPROFILE" fullword ascii 
   
   condition:

      uint16(0) == 0x5a4d and 
      filesize < 2000KB and 
      all of them
}
