rule Linux_Rootkit_Melofee_25d42bdd {
    meta:
        id = "57bw3E2fWbjHPkIVzwAeuw"
        fingerprint = "v1_sha256_5af18434295e80403c3587165cd9db3b771d8f06eaa467e1161a0cd213446bee"
        version = "1.0"
        date = "2024-11-14"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Melofee"
        reference_sample = "5830862707711a032728dfa6a85c904020766fa316ea85b3eef9c017f0e898cc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "hide_proc"
        $str2 = "find_hide_name"
        $str3 = "hide_module"
        $str4 = "unhide_chdir"
        $str5 = "hide_content"
        $str6 = "hidden_chdirs"
        $str7 = "hidden_tcp_conn"
        $str8 = "HIDETAGOUT"
        $str9 = "HIDETAGIN"
    condition:
        4 of them
}

