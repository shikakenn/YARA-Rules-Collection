rule Linux_Proxy_Frp_4213778f {
    meta:
        id = "3tzMvdf27ZFkA0PA9l4KMB"
        fingerprint = "v1_sha256_83eeb632026c38ac08357c27d971da31fbc9a0500ecf489e8332ac5862a77b85"
        version = "1.0"
        date = "2021-10-20"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Proxy.Frp"
        reference_sample = "16294086be1cc853f75e864a405f31e2da621cb9d6a59f2a71a2fca4e268b6c2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $s1 = "github.com/fatedier/frp/client/proxy.TcpProxy"
        $s2 = "frp/cmd/frpc/sub/xtcp.go"
        $s3 = "frp/client/proxy/proxy_manager.go"
        $s4 = "fatedier/frp/models/config/proxy.go"
        $s5 = "github.com/fatedier/frp/server/proxy"
        $s6 = "frp/cmd/frps/main.go"
        $p1 = "json:\"remote_port\""
        $p2 = "remote_port"
        $p3 = "remote_addr"
        $p4 = "range section [%s] local_port and remote_port is necessary[ERR]"
    condition:
        2 of ($s*) and 2 of ($p*)
}

