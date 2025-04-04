rule apt_blackenergy_pdb {
   
    meta:
        id = "2J3pD1I1f9o1Mh3dsuRgLj"
        fingerprint = "v1_sha256_7bb85d03d8f2a4d91554f7fea96e9bbe36b153cfa4a91fd13fb99d41d430c9e9"
        version = "1.0"
        date = "2013-02-15"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the BlackEnergy trojan"
        category = "MALWARE"
        malware_type = "TROJAN"
        actor_type = "CRIMEWARE"
        reference = "https://www.kaspersky.com.au/resource-center/threats/blackenergy"
        hash = "4b2efcda5269f4b80dc417a2b01332185f2fafabd8ba7114fa0306baaab5a72d"
        rule_version = "v1"
        malware_family = "Trojan:W32/BlackEngergy"
        actor_group = "Unknown"

   strings:

      $s1 = "msiexec.exe /i \"%s\" %s REBOOT=\"ReallySuppress\"" fullword wide
      $s2 = "InstallUpdate: CreateProcess failed, Cmdline=%s Error=%d ." fullword wide
      $s3 = "Portuguese=Instalando o Tempo de Execu" fullword wide
      $s4 = "Initialization: Failed to initialize - Unable to get Upgrade Code." fullword wide
      $s5 = "This version of Internet Explorer is not supported.  You should upgrade Internet Explorer to version %s and run setup again.  Se" wide
      $s6 = "Initialization: Failed to open %s file, Make sure the file is not used by another process." fullword wide
      $s7 = "o %s e execute a configura" fullword wide
      $s8 = "Initialization: Failed to initialize - Unable to get Product Version." fullword wide
      $s9 = "f:\\CB\\11X_Security\\Acrobat\\Installers\\BootStrapExe_Small\\Release\\Setup.pdb" fullword ascii
      $s10 = "BootStrap.log" fullword wide
      $s11 = "ACDownloaderDlg" fullword ascii
      $s12 = "Initialization: Failed to initialize Product - msi key not specified." fullword wide
      $s13 = "rio atualizar para o Service Pack %s e executar a instala" fullword wide
      $s14 = "\\Msi.dll" fullword wide
  
   condition:
      
      uint16(0) == 0x5a4d and 
      filesize < 2000KB and 
      all of them
}
