rule Linux_Backdoor_Fontonlake_fe916a45 {
    meta:
        id = "2HQ7mr7Jqvz9CJzpXoVKyP"
        fingerprint = "v1_sha256_590b28264345ea0bdbd53791f422cb4f1fad143df2b790824fc182356a568d7d"
        version = "1.0"
        date = "2021-10-12"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Backdoor.Fontonlake"
        reference_sample = "8a0a9740cf928b3bd1157a9044c6aced0dfeef3aa25e9ff9c93e113cbc1117ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = ".cmd.Upload_Passwd.PasswordInfo" fullword
        $a2 = "Upload_Passwd" fullword
        $a3 = "upload_file_beg" fullword
        $a4 = "upload_file_ing" fullword
        $a5 = "upload_file_end" fullword
        $a6 = "modify_file_attr" fullword
        $a7 = "modify_file_time" fullword
        $a8 = "import platform;print(platform.linux_distribution()[0]);print(platform.linux_distribution()[1]);print(platform.release())" fullword
        $a9 = "inject.so" fullword
        $a10 = "rm -f /tmp/%s" fullword
        $a11 = "/proc/.dot3" fullword
    condition:
        4 of them
}

