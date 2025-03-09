//more info at reversecodes.wordpress.com
rule DMALocker
{
    meta:
        id = "4KaVtAKcIy6HE3hRm1FDs7"
        fingerprint = "v1_sha256_31e0fdc140cc0a795decab1b3aaf5c854c24a0b0ccb03e2defc8b016f787f781"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Description = "Deteccion del ransomware DMA Locker desde la version 1.0 a la 4.0"
        Author = "SadFud"
        Date = "30/05/2016"

    strings:
    $uno = { 41 42 43 58 59 5a 31 31 }
      $dos = { 21 44 4d 41 4c 4f 43 4b }
      $tres = { 21 44 4d 41 4c 4f 43 4b 33 2e 30 }
      $cuatro = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    any of them
    
}
