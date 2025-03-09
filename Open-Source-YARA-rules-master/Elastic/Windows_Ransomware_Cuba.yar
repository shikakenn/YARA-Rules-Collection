rule Windows_Ransomware_Cuba {
    meta:
        id = "78K4J9Zv699wVXYhuFsrnx"
        fingerprint = "v1_sha256_0ba258fdb7db46bd434047e924a607ee9b5857c344d819ce9570c495f5c7aeb9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        os = "Windows"
        arch = "x86"
        category_type = "Ransomware"
        family = "Cuba"
        threat_name = "Windows.Ransomware.Cuba"
        Reference_sample = "33352a38454cfc247bc7465bf177f5f97d7fd0bd220103d4422c8ec45b4d3d0e"
        Reference = "https://www.elastic.co/security-labs/cuba-ransomware-malware-analysis"

    strings:
       $a1 = { 45 EC 8B F9 8B 45 14 89 45 F0 8D 45 E4 50 8D 45 F8 66 0F 13 }
       $a2 = { 8B 06 81 38 46 49 44 45 75 ?? 81 78 04 4C 2E 43 41 74 }
     $b1 = "We also inform that your databases, ftp server and file server were downloaded by us to our     servers." ascii fullword
       $b2 = "Good day. All your files are encrypted. For decryption contact us." ascii fullword
       $b3 = ".cuba" wide fullword

    condition:
        any of ($a*) or all of ($b*)
}
