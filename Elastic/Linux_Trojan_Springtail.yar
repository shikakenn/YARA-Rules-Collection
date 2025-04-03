rule Linux_Trojan_Springtail_35d5b90b {
    meta:
        id = "wzSXLSGApI5Z2HonuGBxw"
        fingerprint = "v1_sha256_7158e60aedfde884d9ee01457abfe6d9b6b1df9cdc1c415231d98429866eaa6c"
        version = "1.0"
        date = "2024-05-18"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Springtail"
        reference_sample = "30584f13c0a9d0c86562c803de350432d5a0607a06b24481ad4d92cdf7288213"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $systemd1 = "Description=syslogd"
        $systemd2 = "ExecStart=/bin/sh -c \"/var/log/syslogd\""
        $cron1 = "cron.txt@reboot"
        $cron2 = "/bin/shcrontab"
        $cron3 = "type/var/log/syslogdcrontab cron.txt"
        $uri = "/mir/index.php"
    condition:
        all of them
}

