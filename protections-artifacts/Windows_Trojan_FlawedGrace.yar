rule Windows_Trojan_FlawedGrace_8c5eb04b {
    meta:
        id = "1RVVFef7Ihd7ivxsFwwmzZ"
        fingerprint = "v1_sha256_dc07197cb9a02ff8d271f78756c2784c74d09e530af20377a584dbfe77e973aa"
        version = "1.0"
        date = "2023-11-01"
        modified = "2023-11-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.FlawedGrace"
        reference_sample = "966112f3143d751a95c000a990709572ac8b49b23c0e57b2691955d6fda1016e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Grace finalized, no more library calls allowed." ascii fullword
        $a2 = ".?AVReadThread@TunnelIO@NS@@" ascii fullword
        $a3 = ".?AVTunnelClientDirectIO@NS@@" ascii fullword
        $a4 = ".?AVWireClientConnectionThread@NS@@" ascii fullword
        $a5 = ".?AVWireParam@NS@@" ascii fullword
    condition:
        3 of them
}

