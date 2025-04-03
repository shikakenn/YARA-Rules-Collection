rule Multi_Hacktool_Gsocket_761d3a0f {
    meta:
        id = "7i4EZYU97Phkh54ZhQWss3"
        fingerprint = "v1_sha256_6f60b63f406b42ac2a43cbe3afbbc98789504d7c6036d50f852a5bc4a6c46cef"
        version = "1.0"
        date = "2024-09-20"
        modified = "2024-11-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Hacktool.Gsocket"
        reference_sample = "193efd61ae10f286d06390968537fa85e4df40995fd424d1afe426c089d172ab"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $str1 = "gsocket: gs_funcs not found"
        $str2 = "/share/gsocket/gs_funcs"
        $str3 = "$GSOCKET_ARGS"
        $str4 = "GSOCKET_SECRET"
        $str5 = "GS_HIJACK_PORTS"
        $str6 = "sftp -D gs-netcat"
        $str7 = "GS_NETCAT_BIN"
        $str8 = "GSOCKET_NO_GREETINGS"
        $str9 = "GS-NETCAT(1)"
        $str10 = "GSOCKET_SOCKS_IP"
        $str11 = "GSOCKET_SOCKS_PORT"
        $str12 = "gsocket(1)"
        $str13 = "gs-sftp(1)"
        $str14 = "gs-mount(1)"
    condition:
        3 of them
}

