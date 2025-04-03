rule Linux_Backdoor_Generic_babf9101 {
    meta:
        id = "7cibbdVW7W3vY5mNlEspcs"
        fingerprint = "v1_sha256_40084f3bed66c1d4a1cd2ffca99fd6789c8ed2db04031e4d4a4926b41d622355"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Backdoor.Generic"
        reference_sample = "9ea73d2c2a5f480ae343846e2b6dd791937577cb2b3d8358f5b6ede8f3696b86"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C4 10 89 45 F4 83 7D F4 00 79 1F 83 EC 0C 68 22 }
    condition:
        all of them
}

rule Linux_Backdoor_Generic_5776ae49 {
    meta:
        id = "4311amLfiwwn6U5XbVEmn8"
        fingerprint = "v1_sha256_b606f12c47182d80e07f8715639c3cc73753274bd8833cb9f6380879356a2b12"
        version = "1.0"
        date = "2021-04-06"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Backdoor.Generic"
        reference_sample = "e247a5decb5184fd5dee0d209018e402c053f4a950dae23be59b71c082eb910c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 18 C1 E8 08 88 47 12 8B 46 18 88 47 13 83 C4 1C 5B 5E 5F 5D }
    condition:
        all of them
}

