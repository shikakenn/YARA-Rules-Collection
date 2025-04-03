rule MacOS_Trojan_Thiefquest_9130c0f3 {
    meta:
        id = "75tQZl6FUJnvCU2OzVmoge"
        fingerprint = "v1_sha256_20e9ea15a437a17c4ef68f2472186f6d1ab3118d5b392f84fcb2bd376ec3863a"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "bed3561210e44c290cd410adadcdc58462816a03c15d20b5be45d227cd7dca6b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = "heck_if_targeted" ascii fullword
        $a2 = "check_command" ascii fullword
        $a3 = "askroot" ascii fullword
        $a4 = "iv_rescue_data" ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_fc2e1271 {
    meta:
        id = "4ZHh547LyzuMsPHwcDOrtC"
        fingerprint = "v1_sha256_a20c76e53874fc0fec5fd2660c63c6f1e7c1b2055cbd2a9efdfd114cd6bdda5c"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 30 30 30 42 67 7B 30 30 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_86f9ef0c {
    meta:
        id = "1haxKxmCKNQtBfwmwfDEnO"
        fingerprint = "v1_sha256_426d533d39e594123f742b15d0a93ded986b9b308685f7b2cfaf5de0b32cdbff"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "59fb018e338908eb69be72ab11837baebf8d96cdb289757f1f4977228e7640a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 6C 65 31 6A 6F 57 4E 33 30 30 30 30 30 33 33 00 30 72 7A 41 43 47 33 57 72 7C }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_40f9c1c3 {
    meta:
        id = "1kc9p9ByWOFPK6sXFHHqz5"
        fingerprint = "v1_sha256_546edc2d6d715eac47e7a8d3ceb91cf314fa6dbee04f0475a5c4a84ba53fd722"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "e402063ca317867de71e8e3189de67988e2be28d5d773bbaf75618202e80f9f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 7C 49 56 7C 6A 30 30 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_0f9fe37c {
    meta:
        id = "5x2xzDOjrbWYL9KZKUGZti"
        fingerprint = "v1_sha256_84f9e8938d7e2b0210003fc8334b8fa781a40afffeda8d2341970b84ed5d3b5a"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 71 6B 6E 6C 55 30 55 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_1f4bac78 {
    meta:
        id = "xiIATXkeATJJy3RZBUMKr"
        fingerprint = "v1_sha256_96db33e135138846f978026867bb2536226539997d060f41e7081f7f29b66c85"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 32 33 4F 65 49 66 31 68 }
    condition:
        all of them
}

