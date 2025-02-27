rule apt_auriga_driver {
   
    meta:
        id = "1E9HsCnCwFkL71xeXo5q58"
        fingerprint = "v1_sha256_c027073ba398fe89d418be67f0850c8d9e4d4c50a991c45b84cdb416497ccf1c"
        version = "1.0"
        date = "2013-03-13"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Auriga driver"
        category = "INFO"
        reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
        hash = "207eee627a76449ac6d2ca43338d28087c8b184e7b7b50fdc60a11950c8283ec"
        rule_version = "v1"
        malware_family = "Driver:W32/Auriga"
        actor_group = "APT1"

   strings:
   
      $s1 = "\\SystemRoot\\System32\\netui.dll" fullword wide
      $s2 = "\\SystemRoot\\System32\\drivers\\riodrv32.sys" fullword wide
      $s3 = "\\SystemRoot\\System32\\arp.exe" fullword wide
      $s4 = "netui.dll" fullword ascii
      $s5 = "riodrv32.sys" fullword wide
      $s6 = "\\netui.dll" fullword wide
      $s7 = "d:\\drizt\\projects\\auriga\\branches\\stone_~1\\server\\exe\\i386\\riodrv32.pdb" fullword ascii
      $s8 = "\\riodrv32.sys" fullword wide
      $s9 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\riodrv32" fullword wide
      $s10 = "\\DosDevices\\rio32drv" fullword wide
      $s11 = "e\\Driver\\nsiproxy" fullword wide
      $s12 = "(C) S3/Diamond Multimedia Systems. All rights reserved." fullword wide
      $s13 = "\\Device\\rio32drv" fullword wide
      $s14 = "\\Registry\\Machine\\SOFTWARE\\riodrv" fullword wide
      $s15 = "\\Registry\\Machine\\SOFTWARE\\riodrv32" fullword wide
   
   condition:
   
      uint16(0) == 0x5a4d and 
      filesize < 50KB and 
      all of them
}
