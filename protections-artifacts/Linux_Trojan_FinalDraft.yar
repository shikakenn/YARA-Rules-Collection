rule Linux_Trojan_FinalDraft_4ea5a204 {
    meta:
        id = "fTs2O5A6QYy1kqhjmdpbR"
        fingerprint = "v1_sha256_c632ca74db0f8ad3e046fe2118ba7a199a0f261beaf56b6445183a722e506cad"
        version = "1.0"
        date = "2025-01-23"
        modified = "2025-02-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.FinalDraft"
        reference_sample = "83406905710e52f6af35b4b3c27549a12c28a628c492429d3a411fdb2d28cc8c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str_comm_option_1 = "CBindTcpTransChannel"
        $str_comm_option_2 = "CDnsTransChannel"
        $str_comm_option_3 = "CHttpTransChannel"
        $str_comm_option_4 = "CIcmpTransChannel"
        $str_comm_option_5 = "COutLookTransChannel"
        $str_comm_option_6 = "CReverseTcpTransChannel"
        $str_comm_option_7 = "CReverseUdpTransChannel"
        $str_comm_option_8 = "CWebTransChannel"
        $str_feature_1 = "%s?type=del&id=%s" fullword
        $str_feature_2 = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&grant_type=refresh_token" fullword
        $str_feature_3 = "/var/log/installlog.log.%s" fullword
        $str_feature_4 = "/mnt/hgfsdisk.log.%s" fullword
        $str_feature_5 = "%-10s %-25s %-25s %-15s" fullword
        $str_feature_6 = "%-20s %-10s %-10s %-10s %-30s" fullword
        $str_feature_7 = { 48 39 F2 74 ?? 48 0F BE 0A 48 FF C2 48 6B C0 ?? 48 01 C8 EB ?? }
    condition:
        (1 of ($str_comm_option*)) and (3 of ($str_feature_*))
}

