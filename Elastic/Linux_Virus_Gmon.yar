rule Linux_Virus_Gmon_e544d891 {
    meta:
        id = "2MIh1XIkNZUGO3FeawtFO8"
        fingerprint = "v1_sha256_6dcfd51aaa79d7bac0100d9c891aa4275b8e1f7614cda46a5da4c738d376c729"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Virus.Gmon"
        reference_sample = "d0fe377664aa0bc0d1fd3a307650f211dd3ef2e2f04597abee465e836e6a6f32"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E5 53 51 52 8B 44 24 14 8B 5C 24 18 8B 4C 24 1C 8B 54 24 20 }
    condition:
        all of them
}

rule Linux_Virus_Gmon_192bd9b3 {
    meta:
        id = "1a849q7N7kQp9IRQ0K5bXw"
        fingerprint = "v1_sha256_3df275349d14a845c73087375f96e0c9a069ff685beb89249590ef9448e50373"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Virus.Gmon"
        reference_sample = "d0fe377664aa0bc0d1fd3a307650f211dd3ef2e2f04597abee465e836e6a6f32"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E5 56 53 8B 75 08 8B 5D 0C 8B 4D 10 31 D2 39 CA 7D 11 8A 04 1A 38 }
    condition:
        all of them
}

