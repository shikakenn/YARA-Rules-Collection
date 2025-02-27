rule Linux_Rootkit_Suterusu_94667bf2 {
    meta:
        id = "1fFg3OYpQftyAJXq6emByo"
        fingerprint = "v1_sha256_a02e2d05bc3bee902829087e21dcc7ed19320336c7d66d3938b0b9fd4c298bcb"
        version = "1.0"
        date = "2024-11-14"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Suterusu"
        reference_sample = "753fd579a684e09a70ae0fd147441c45d24a5acae94a78a92e393058c3b69506"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "Hiding PID %hu"
        $str2 = "Unhiding PID %hu"
        $str3 = "Hiding TCPv4 port %hu"
        $str4 = "Unhiding TCPv4 port %hu"
        $str5 = "Hiding TCPv6 port %hu"
        $str6 = "Unhiding TCPv6 port %hu"
        $str7 = "Hiding UDPv4 port %hu"
        $str8 = "Unhiding UDPv4 port %hu"
        $str9 = "Hiding UDPv6 port %hu"
        $str10 = "Unhiding UDPv6 port %hu"
        $str11 = "Hiding file/dir %s"
        $str12 = "Unhiding file/dir %s"
        $func1 = "hide_promisc"
        $func2 = "hidden_tcp6_ports"
        $func3 = "hide_udp4_port"
        $func4 = "unhide_udp6_port"
        $func5 = "hide_tcp4_port"
        $func6 = "hide_tcp6_port"
        $func7 = "hidden_udp4_ports"
        $func8 = "unhide_tcp4_port"
        $func9 = "unhide_file"
        $func10 = "hijack_stop"
        $func11 = "hooked_syms"
        $func12 = "hidden_tcp4_ports"
        $func13 = "unhide_proc"
        $func14 = "unhide_udp4_port"
        $func15 = "unhide_tcp6_port"
        $func16 = "hidden_udp6_ports"
        $func17 = "hijack_pause"
        $func18 = "hijack_start"
        $menu1 = "Hide process with pid [ARG]"
        $menu2 = "Unhide process with pid [ARG]"
        $menu3 = "Hide TCP 4 port [ARG]"
        $menu4 = "Unhide TCP 4 port [ARG]"
        $menu5 = "Hide UDPv4 port [ARG]"
        $menu6 = "Unhide UDPv4 port [ARG]"
        $menu7 = "Hide TCPv6 port [ARG]"
        $menu8 = "Unhide TCPv6 port [ARG]"
        $menu9 = "Hide UDPv4 port [ARG]"
        $menu10 = "Unhide UDPv6 port [ARG]"
        $menu11 = "Hide file/directory named [ARG]"
        $menu12 = "Unhide file/directory named [ARG]"
    condition:
        4 of ($str*) or 6 of ($func*) or 4 of ($menu*)
}

