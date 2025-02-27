rule MacOS_Trojan_RustBucket_e64f7a92 {
    meta:
        id = "4CfmSyZuJGfImtFp1HQsiP"
        fingerprint = "v1_sha256_bd6005d72faba6aaeebdcbd8c771995cbfc667faf01eb93825afe985954a47fc"
        version = "1.0"
        date = "2023-06-26"
        modified = "2023-06-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket"
        threat_name = "MacOS.Trojan.RustBucket"
        reference_sample = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $user_agent = "User-AgentMozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"
        $install_log = "/var/log/install.log"
        $timestamp = "%Y-%m-%d %H:%M:%S"
    condition:
        all of them
}

