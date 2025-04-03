rule CISA_10376640_03 : trojan wiper worm HERMETICWIZARD
{
    meta:
        id = "3XEo3RoOOfDlRH5nM2uMpE"
        fingerprint = "v1_sha256_e6c41f77a0e2daaefde9ed3bad7aad1f070480ccf030be9f4099fd87c0ffdc26"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "CISA Code & Media Analysis"
        Incident = "10376640"
        Date = "2022-03-13"
        Last_Modified = "20220413_1300"
        Actor = "n/a"
        Category = "Trojan Wiper Worm"
        Family = "HERMETICWIZARD"
        Description = "Detects Hermetic Wizard samples"
        Reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-115b"
        MD5_1 = "58d71fff346017cf8311120c69c9946a"
        SHA256_1 = "2d29f9ca1d9089ba0399661bb34ba2fd8aba117f04678cd71856d5894aa7150b"

   strings:
       $s0 = { 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F }
       $s1 = { 5C 00 5C 00 25 00 73 00 5C 00 70 00 69 00 70 00 65 00 5C 00 25 00 73 }
       $s2 = { 64 00 6C 00 6C 00 00 00 2D 00 69 }
       $s3 = { 2D 00 68 00 00 00 00 00 2D 00 73 }
       $s4 = { 2D 00 63 00 00 00 00 00 2D 00 61 }
       $s5 = { 43 6F 6D 6D 61 6E 64 4C 69 6E 65 54 6F 41 72 67 76 57 }
   condition:
       all of them
}
