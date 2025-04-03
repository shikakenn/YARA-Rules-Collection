rule MacOS_Backdoor_Applejeus_31872ae2 {
    meta:
        id = "2FXrunBNv7M9UVLyMEIkoi"
        fingerprint = "v1_sha256_1d6f06668a7d048a93e53b294c5ab8ffe4cd610f3bef3fd80f14425ef8a85a29"
        version = "1.0"
        date = "2021-10-18"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Backdoor.Applejeus"
        reference_sample = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { FF CE 74 12 89 F0 31 C9 80 34 0F 63 48 FF C1 48 39 C8 75 F4 }
    condition:
        all of them
}

