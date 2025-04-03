/*
    Yara Rule Set
    Author: Symantec
    Date: 2016-08-08
    Identifier: Strider
*/

rule remsec_executable_blob_32 {
    meta:
        id = "37DhmYmMUtmvNT5zDZAW4S"
        fingerprint = "v1_sha256_1cfc43ab15b3d220a636c150315c30f5654e53fad67d20534ce4d5c00295e35e"
        version = "1.0"
        score = 80
        date = "2016/08/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects malware from Symantec's Strider APT report"
        category = "INFO"
        reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
        copyright = "Symantec"

   strings:
      $code = { 31 06 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 F0 }
   condition:
      all of them
}

rule remsec_executable_blob_64 {
    meta:
        id = "4KLOxtnIHCNanGcxobV8LW"
        fingerprint = "v1_sha256_957e5b6afabec3fb1b169dd85d0e950107e219f7dec8ef779a18bd90d9824a97"
        version = "1.0"
        score = 80
        date = "2016/08/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects malware from Symantec's Strider APT report"
        category = "INFO"
        reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
        copyright = "Symantec"

   strings:
      $code = { 31 06 48 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 EF }
   condition:
      all of them
}

rule remsec_executable_blob_parser {
    meta:
        id = "3dBaVKyswEDkQyABVMThUR"
        fingerprint = "v1_sha256_2f6db962807c07ff1bbe8b53eeb386d7b0ac88f95b76439c0d8b65d597739bdd"
        version = "1.0"
        score = 80
        date = "2016/08/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects malware from Symantec's Strider APT report"
        category = "INFO"
        reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
        copyright = "Symantec"

   strings:
      $code = { ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) 04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }
   condition:
      all of them
}

rule remsec_encrypted_api {
    meta:
        id = "64WdpEZjM9S6qwGpFXZmSY"
        fingerprint = "v1_sha256_4f10c24a8480c17c2939fe3fecba2820b22f8a47bc2b2e73ac1080a355025d7c"
        version = "1.0"
        score = 80
        date = "2016/08/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects malware from Symantec's Strider APT report"
        category = "INFO"
        reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
        copyright = "Symantec"

   strings:
      $open_process = { 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }
   condition:
      all of them
}

rule remsec_packer_A {
    meta:
        id = "2Wc3ZNS5jp54UbWx9d6It3"
        fingerprint = "v1_sha256_b46a41686fbf1c63e8a8b583859f23bf789bc9f11ee6b1fb01bb08e602772e76"
        version = "1.0"
        score = 80
        date = "2016/08/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects malware from Symantec's Strider APT report"
        category = "INFO"
        reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
        copyright = "Symantec"

   strings:
      $code = { 69 ( C? | D? | E? | F? ) AB 00 00 00 ( 81 | 41 81 ) C? CD 2B 00 00 ( F7 | 41 F7 ) E? ( C1 | 41 C1 ) E? 0D ( 69 | 45 69 ) ( C? | D? | E? | F? ) 85 CF 00 00 ( 29 | 41 29 | 44 29 | 45 29 | 2B | 41 2B | 44 2B | 45 2B ) }
   condition:
      all of them
}

rule remsec_packer_B {
    meta:
        id = "6vT8zvdI23Tobd7TJ6cu8j"
        fingerprint = "v1_sha256_9c63b5934d60b59a33364ef56c913220e59b9798a682a7f97e6755270adf4e4b"
        version = "1.0"
        score = 80
        date = "2016/08/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects malware from Symantec's Strider APT report"
        category = "INFO"
        reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
        copyright = "Symantec"

   strings:
      $code = { 48 8B 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 05 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 89 44 24 ?? 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) ( 44 88 6? 24 ?? | C6 44 24 ?? 00 ) 48 89 44 24 ?? 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) C7 44 24 ?? 0? 00 00 00 2B ?8 48 89 ?C 24 ?? 44 89 6? 24 ?? 83 C? 08 89 ?C 24 ?? ( FF | 41 FF ) D? ( 05 | 8D 88 ) 00 00 00 3A }
   condition:
      all of them
}
