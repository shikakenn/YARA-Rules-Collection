rule Ryuk_Ransomware {

    meta:
        id = "1ByMzRqavt9q1ZHZLcDq1q"
        fingerprint = "v1_sha256_43c0be708fa8a388dce6e1dd721e24329b5b08a942d99e9b2631c90155790c4b"
        version = "1.0"
        date = "2019-04-25"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Christiaan Beek - McAfee ATR team"
        description = "Ryuk Ransomware hunting rule"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/ryuk-ransomware-attack-rush-to-attribution-misses-the-point/"
        rule_version = "v2"
        malware_family = "Ransom:W32/Ryuk"
        actor_group = "Unknown"

   strings:

      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "\\System32\\cmd.exe" fullword wide
      $s1 = "C:\\Users\\Admin\\Documents\\Visual Studio 2015\\Projects\\ConsoleApplication54new crypted" ascii
      $s2 = "fg4tgf4f3.dll" fullword wide
      $s3 = "lsaas.exe" fullword wide
      $s4 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s5 = "\\Documents and Settings\\Default User\\finish" fullword wide
      $s6 = "\\users\\Public\\sys" fullword wide
      $s7 = "\\users\\Public\\finish" fullword wide
      $s8 = "You will receive btc address for payment in the reply letter" fullword ascii
      $s9 = "hrmlog" fullword wide
      $s10 = "No system is safe" fullword ascii
      $s11 = "keystorage2" fullword wide
      $s12 = "klnagent" fullword wide
      $s13 = "sqbcoreservice" fullword wide
      $s14 = "tbirdconfig" fullword wide
      $s15 = "taskkill" fullword wide

      $op0 = { 8b 40 10 89 44 24 34 c7 84 24 c4 }
      $op1 = { c7 44 24 34 00 40 00 00 c7 44 24 38 01 }
    
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)) or
      ( all of them )
}

rule Ransom_Ryuk_sept2020 {
    meta:
        id = "n8TUU6BmaRSb3tERyalHS"
        fingerprint = "v1_sha256_73dca6f3cacedfba49b8293b0acac0cf50c6fb924391e5ca4dc3c1b433ccd89c"
        version = "1.0"
        date = "2020-10-13"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfe ATR"
        description = "Detecting latest Ryuk samples"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        malware_family = "Ransom:W32/Ryuk"
        actor_group = "Unknown"
        hash1 = "cfdc2cb47ef3d2396307c487fc3c9fe55b3802b2e570bee9aea4ab1e4ed2ec28"

   strings:
      $x1 = "\" /TR \"C:\\Windows\\System32\\cmd.exe /c for /l %x in (1,1,50) do start wordpad.exe /p " fullword ascii
      $x2 = "cmd.exe /c \"bcdedit /set {default} recoveryenabled No & bcdedit /set {default}\"" fullword ascii
      $x3 = "cmd.exe /c \"bootstatuspolicy ignoreallfailures\"" fullword ascii
      $x4 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet\"" fullword ascii
      $x5 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x6 = "cmd.exe /c \"WMIC.exe shadowcopy delete\"" fullword ascii
      $x7 = "/C REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /t REG_SZ /d \"" fullword wide
      $x8 = "W/C REG DELETE \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /f" fullword wide
      $x9 = "\\System32\\cmd.exe" fullword wide
      $s10 = "Ncsrss.exe" fullword wide
      $s11 = "lsaas.exe" fullword wide
      $s12 = "lan.exe" fullword wide
      $s13 = "$WGetCurrentProcess" fullword ascii
      $s14 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s15 = "Ws2_32.dll" fullword ascii
      $s16 = " explorer.exe" fullword wide
      $s17 = "e\\Documents and Settings\\Default User\\" fullword wide
      $s18 = "\\users\\Public\\" fullword ascii
      $s19 = "\\users\\Public\\sys" fullword wide
      $s20 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii

      $seq0 = { 2b c7 50 e8 30 d3 ff ff ff b6 8c }
      $seq1 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
      $seq2 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
   condition:
      ( uint16(0) == 0x5a4d and 
      filesize < 400KB and 
      ( 1 of ($x*) and 5 of them ) and 
      all of ($seq*)) or ( all of them )
}

rule RANSOM_RYUK_May2021 : ransomware
{
    meta:
        id = "5jxmWgofmbsF07RjOrMlsL"
        fingerprint = "v1_sha256_b379c1182e60ce8c777668386d8cbd08350dd2363770dec56502bf44aaf5d7f6"
        version = "0.1"
        date = "2021-05-21"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Elias | McAfee ATR Team"
        description = "Rule to detect latest May 2021 compiled Ryuk variant"
        category = "INFO"
        hash = "8f368b029a3a5517cb133529274834585d087a2d3a5875d03ea38e5774019c8a"

    strings:
        $ryuk_filemarker = "RYUKTM" fullword wide ascii
        
        $sleep_constants = { 68 F0 49 02 00 FF (15|D1) [0-4] 68 ?? ?? ?? ?? 6A 01 }
        $icmp_echo_constants = { 68 A4 06 00 00 6A 44 8D [1-6] 5? 6A 00 6A 20 [5-20] FF 15 }
        
    condition:
        uint16(0) == 0x5a4d
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 200KB
        and ( $ryuk_filemarker
        or ( $sleep_constants 
        and $icmp_echo_constants ))
}
