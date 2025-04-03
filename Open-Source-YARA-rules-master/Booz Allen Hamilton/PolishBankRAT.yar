rule PolishBankRAT_srservice_xorloop {
    meta:
        id = "5wHuSHQzjwhAUQO7E7nClH"
        fingerprint = "v1_sha256_38f5b09ff455e43f21626bf00d4aa80d27181c13d6cf20a2ed9b89c33a4c3b28"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Booz Allen Hamilton Dark Labs"
        description = "Finds the custom xor decode loop for <PolishBankRAT-srservice>"
        category = "INFO"
        reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"

strings:
    $loop = { 48 8B CD E8 60 FF FF FF 48 FF C3 32 44 1E FF 48 FF CF 88 43 FF }
condition:
    (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $loop
}

rule PolishBankRAT_fdsvc_xor_loop {
    meta:
        id = "3bA8emmOFKwwVTiBW27owg"
        fingerprint = "v1_sha256_735543d2a180cebeb0fa146e67533b113adb14470fb76dbfe9683ab2358fe449"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Booz Allen Hamilton Dark Labs"
        description = "Finds the custom xor decode loop for <PolishBankRAT-fdsvc>"
        category = "INFO"
        reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"

strings:
    $loop = {0F B6 42 FF 48 8D 52 FF 30 42 01 FF CF 75 F1}
condition:
    (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $loop
}

rule PolishBankRAT_fdsvc_decode2 {
    meta:
        id = "2nUC6ZHwQkf0RMus5h1EUJ"
        fingerprint = "v1_sha256_9922b5b262894a7b0e60ef7b023d82e4282be654e4c14c30f65eb1f944976bd9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Booz Allen Hamilton Dark Labs"
        description = "Find a constant used as part of a payload decoding function in PolishBankRAT-fdsvc"
        category = "INFO"
        reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"

strings:
    $part1 = {A6 EB 96}
    $part2 = {61 B2 E2 EF}
    $part3 = {0D CB E8 C4}
    $part4 = {5A F1 66 9C}
    $part5 = {A4 80 CD 9A}
    $part6 = {F1 2F 46 25}
    $part7 = {2F DB 16 26}
    $part8 = {4B C4 3F 3C}
    $str1 = "This program cannot be run in DOS mode"
condition:
    (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule decoded_PolishBankRAT_fdsvc_strings {
    meta:
        id = "4HaETZ2Egw0KibdAcFFPoo"
        fingerprint = "v1_sha256_60769a6e0ea8dd8ff05c2e6c03f424b8abb7f910c41065ca99d6c5da5f2088bc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Booz Allen Hamilton Dark Labs"
        description = "Finds hard coded strings in PolishBankRAT-fdsvc"
        category = "INFO"
        reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"

strings:
    $str1 = "ssylka" wide ascii
    $str2 = "ustanavlivat" wide ascii
    $str3 = "poluchit" wide ascii
    $str4 = "pereslat" wide ascii
    $str5 = "derzhat" wide ascii
    $str6 = "vykhodit" wide ascii
    $str7 = "Nachalo" wide ascii
condition:
    (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and 4 of ($str*)
}
