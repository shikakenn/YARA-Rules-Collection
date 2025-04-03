rule MacOS_Trojan_Genieo_5e0f8980 {
    meta:
        id = "5T8WXw7gDtstQHkil9ZSzR"
        fingerprint = "v1_sha256_76b725f6ae5755bb00d384ef2ae1511789487257d8bb7cb61b893226f03a803e"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "6c698bac178892dfe03624905256a7d9abe468121163d7507cade48cf2131170"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 00 CD 01 1E 68 57 58 D7 56 7C 62 C9 27 3C C6 15 A9 3D 01 02 2F E1 69 B5 4A 11 }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_37878473 {
    meta:
        id = "4IFa1OiutrUbYuepbjyCD7"
        fingerprint = "v1_sha256_bb04ae4e0a98e0dbd0c0708d5e767306e38edf76de2671523f4bd43cbcbfefc2"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "0fadd926f8d763f7f15e64f857e77f44a492dcf5dc82ae965d3ddf80cd9c7a0d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 65 72 6E 61 6C 44 6F 77 6E 4C 6F 61 64 55 72 6C 46 6F 72 42 72 61 6E 64 3A 5D }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_0d003634 {
    meta:
        id = "6RMgD9UWAWkwyV9tFDFmlZ"
        fingerprint = "v1_sha256_0412f88408fb14d1126ef091d0a5cc0ee2b2e39aeb241bef55208b59830ca993"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "bcd391b58338efec4769e876bd510d0c4b156a7830bab56c3b56585974435d70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 75 69 6C 64 2F 41 6E 61 62 65 6C 50 61 63 6B 61 67 65 2F 62 75 69 6C 64 2F 73 }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_9e178c0b {
    meta:
        id = "oLtHT7LFB7xbYFwIsfjOJ"
        fingerprint = "v1_sha256_212f96ca964aceeb80c6d3282d488cfbb74aeffb9c0c9dd840a3a28f9bbdcbea"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "b7760e73195c3ea8566f3ff0427d85d6f35c6eec7ee9184f3aceab06da8845d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 4D 49 70 67 41 59 4B 6B 42 5A 59 53 65 4D 6B 61 70 41 42 48 4D 5A 43 63 44 44 }
    condition:
        all of them
}

