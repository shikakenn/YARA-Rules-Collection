rule Linux_Trojan_Chinaz_a2140ca1 {
    meta:
        id = "2F930uhmnVKzpXUoSwyfKi"
        fingerprint = "v1_sha256_c9c63114e45b45b1c243af1f719cddc838a06a1f35d65dca6a2fb5574047eff0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Chinaz"
        reference_sample = "7c44c2ca77ef7a62446f6266a757817a6c9af5e010a219a43a1905e2bc5725b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 53 8B 74 24 0C 8B 5C 24 10 8D 74 26 00 89 C2 89 C1 C1 FA 03 83 }
    condition:
        all of them
}

