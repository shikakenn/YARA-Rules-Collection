rule Linux_Rootkit_Fontonlake_8fa41f5e {
    meta:
        id = "1cL0Dgz7Zvd4PwglvpIFjn"
        fingerprint = "v1_sha256_e90ace26dd74ae948d2469c6f532af5ec3070a21092f8b2c4d47c4f5b9d04c09"
        version = "1.0"
        date = "2021-10-12"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Fontonlake"
        reference_sample = "826222d399e2fb17ae6bc6a4e1493003881b1406154c4b817f0216249d04a234"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "kernel_write" fullword
        $a2 = "/proc/.dot3" fullword
        $a3 = "hide_pid" fullword
        $h2 = "s_hide_pids" fullword
        $h3 = "s_hide_tcp4_ports" fullword
        $h4 = "s_hide_strs" fullword
        $tmp1 = "/tmp/.tmH" fullword
        $tmp2 = "/tmp/.tmp_" fullword
    condition:
        (all of ($a*) and 1 of ($tmp*)) or (all of ($h*))
}

