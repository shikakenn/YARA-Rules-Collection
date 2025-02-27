rule Linux_Trojan_Cerbu_69d5657e {
    meta:
        id = "2LlnaxPXo1T8A7RpcvyysJ"
        fingerprint = "v1_sha256_644e8d5a1b5c8618e71497f21b0244215924e293e274b9164692dd927cd74ba8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Cerbu"
        reference_sample = "f10bf3cf2fdfbd365d3c2d8dedb2d01b85236eaa97d15370dbcb5166149d70e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 5B 5E C9 C3 55 89 E5 83 EC 08 83 C4 FC FF 75 0C 6A 05 FF }
    condition:
        all of them
}

