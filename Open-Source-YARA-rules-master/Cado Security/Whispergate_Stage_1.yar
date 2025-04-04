rule Whispergate_Stage_1 {
    meta:
        id = "60fR8EucB3ZufrTQ8Jcxh2"
        fingerprint = "v1_sha256_b8d8f2f56fe3a6f42699b7736386f9e8083fc728d06750f51064be1ff2f6620b"
        version = "1.0"
        date = "2022-01-17"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mmuir@cadosecurity.com"
        description = "Detects first stage payload from WhisperGate"
        category = "INFO"
        report = "HTTPS://GITHUB.COM/CADO-SECURITY/DFIR_RESOURCES_WHISPERGATE"
        hash = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
        license = "Apache License 2.0"

    strings:
      $a = { 31 41 56 4E 4D 36 38 67 6A 36 50 47 50 46 63 4A 75 66 74 4B 41 54 61 34 57 4C 6E 7A 67 38 66 70 66 76 }
      $b = { 38 42 45 44 43 34 31 31 30 31 32 41 33 33 42 41 33 34 46 34 39 31 33 30 44 30 46 31 38 36 39 39 33 43 36 41 33 32 44 41 44 38 39 37 36 46 36 41 35 44 38 32 43 31 45 44 32 33 30 35 34 43 30 35 37 45 43 45 44 35 34 39 36 46 36 35 }
      $c = { 24 31 30 6B 20 76 69 61 20 62 69 74 63 6F 69 6E 20 77 61 6C 6C 65 74 }
      $d = { 74 6F 78 20 49 44 }
    condition:
      uint16(0) == 0x5A4D and all of them
}
