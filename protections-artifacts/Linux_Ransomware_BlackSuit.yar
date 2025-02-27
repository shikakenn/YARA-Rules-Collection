rule Linux_Ransomware_BlackSuit_9f53e7e5 {
    meta:
        id = "3zNQwLUuLWQTr8X4vmeNS4"
        fingerprint = "v1_sha256_121e0139385cfef5dff394c4ea36d950314b00c6d7021cf2ca667ee942e74763"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.BlackSuit"
        reference_sample = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "esxcli vm process list > list_" fullword
        $a2 = "Drop readme failed: %s(%d)" fullword
        $a3 = "README.BlackSuit.txt" fullword
    condition:
        2 of them
}

