rule kraken_cryptor_ransomware_loader {

    meta:
        id = "3RdFpHIai6XWpjhcaFuS0b"
        fingerprint = "v1_sha256_9e252a3ba7f6bf861ea7563461a1420959dfb0f5b7c3f6071150d03422504539"
        version = "1.0"
        date = "2018-09-30"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Kraken Cryptor Ransomware loader"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
        hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"
        rule_version = "v1"
        malware_family = "Ransom:W32/Kraken"
        actor_group = "Unknown"

   strings:

      $pdb = "C:\\Users\\Krypton\\source\\repos\\UAC\\UAC\\obj\\Release\\UAC.pdb" fullword ascii
      $s2 = "SOFTWARE\\Classes\\mscfile\\shell\\open\\command" fullword wide
      $s3 = "public_key" fullword ascii
      $s4 = "KRAKEN DECRYPTOR" ascii
      $s5 = "UNIQUE KEY" fullword ascii

   condition:

       uint16(0) == 0x5a4d and 
       filesize < 600KB  and 
       $pdb or 
       all of ($s*)
}

rule kraken_cryptor_ransomware {
   
    meta:
        id = "6fxeN9HniqbUqAXdEFguFi"
        fingerprint = "v1_sha256_2ad7f0bf6110eab79e0f9541c49ae44089ebca3f91ffa80de874d60d5a7ed266"
        version = "1.0"
        date = "2018-09-30"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Kraken Cryptor Ransomware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
        hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"
        rule_version = "v1"
        malware_family = "Ransom:W32/Kraken"
        actor_group = "Unknown"

   strings:
     
      $s1 = "Kraken Cryptor" fullword ascii nocase
      $s2 = "support_email" fullword ascii
      $fw1 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii 
      $fw2 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii 
      $fw3 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii 
      $fw4 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii 
      $uac = "<!--<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />-->   " fullword ascii
  
   condition:

      uint16(0) == 0x5a4d and
      filesize < 600KB and
      all of ($fw*) or
      all of ($s*) or
      $uac
}

rule ransom_note_kraken_cryptor_ransomware {
   
    meta:
        id = "2ronNDgqweiQnRKmwBrdc8"
        fingerprint = "v1_sha256_d4acdf0716320b0f757b8dbc97bb9d407460b2d69dc8e12292539e823be0f57d"
        version = "1.0"
        date = "2018-09-30"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the ransom note delivered by Kraken Cryptor Ransomware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
        rule_version = "v1"
        malware_family = "Ransom:W32/Kraken"
        actor_group = "Unknown"

   strings:

      $s1 = "No way to recovery your files without \"KRAKEN DECRYPTOR\" software and your computer \"UNIQUE KEY\"!" fullword ascii
      $s2 = "Are you want to decrypt all of your encrypted files? If yes! You need to pay for decryption service to us!" fullword ascii
      $s3 = "The speed, power and complexity of this encryption have been high and if you are now viewing this guide." fullword ascii
      $s4 = "Project \"KRAKEN CRYPTOR\" doesn't damage any of your files, this action is reversible if you follow the instructions above." fullword ascii
      $s5 = "https://localBitcoins.com" fullword ascii
      $s6 = "For the decryption service, we also need your \"KRAKEN ENCRYPTED UNIQUE KEY\" you can see this in the top!" fullword ascii
      $s7 = "-----BEGIN KRAKEN ENCRYPTED UNIQUE KEY----- " fullword ascii
      $s8 = "All your files has been encrypted by \"KRAKEN CRYPTOR\"." fullword ascii
      $s9 = "It means that \"KRAKEN CRYPTOR\" immediately removed form your system!" fullword ascii
      $s10 = "After your payment made, all of your encrypted files has been decrypted." fullword ascii
      $s11 = "Don't delete .XKHVE files! there are not virus and are your files, but encrypted!" fullword ascii
      $s12 = "You can decrypt one of your encrypted smaller file for free in the first contact with us." fullword ascii
      $s13 = "You must register on this site and click \"BUY Bitcoins\" then choose your country to find sellers and their prices." fullword ascii
      $s14 = "-----END KRAKEN ENCRYPTED UNIQUE KEY-----" fullword ascii
      $s15 = "DON'T MODIFY \"KRAKEN ENCRYPT UNIQUE KEY\"." fullword ascii
      $s16 = "# Read the following instructions carefully to decrypt your files." fullword ascii
      $s17 = "We use best and easy way to communications. It's email support, you can see our emails below." fullword ascii
      $s18 = "DON'T USE THIRD PARTY, PUBLIC TOOLS/SOFTWARE TO DECRYPT YOUR FILES, THIS CAUSE DAMAGE YOUR FILES PERMANENTLY." fullword ascii
      $s19 = "https://en.wikipedia.org/wiki/Bitcoin" fullword ascii
      $s20 = "Please send your message with same subject to both address." fullword ascii
   
   condition:

      uint16(0) == 0x4120 and
      filesize < 9KB and
      all of them 
}
