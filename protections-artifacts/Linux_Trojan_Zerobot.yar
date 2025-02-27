rule Linux_Trojan_Zerobot_185e2396 {
    meta:
        id = "6F8t3cYg5ty6YbVhgcnE73"
        fingerprint = "v1_sha256_caa21cc019d8e4549d976f8b4f98d930ef7acf4c39c41956ae35fa78c975e016"
        version = "1.0"
        date = "2022-12-16"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Strings found in the zerobot startup / persistanse functions"
        category = "INFO"
        threat_name = "Linux.Trojan.Zerobot"
        reference_sample = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $startup_method_1_0 = "/usr/bin/sshf"
        $startup_method_1_1 = "start on filesystem"
        $startup_method_1_2 = "exec /usr/bin/sshf"
        $startup_method_2_0 = "Description=Hehehe"
        $startup_method_2_1 = "/lib/systemd/system/sshf.service"
        $start_service_0 = "service enable sshf"
        $start_service_1 = "systemctl enable sshf"
    condition:
        (all of ($startup_method_1_*) or all of ($startup_method_2_*)) and 1 of ($start_service_*)
}

rule Linux_Trojan_Zerobot_3a5b56dd {
    meta:
        id = "3lRzI2rwlKEs92V7FBQ54a"
        fingerprint = "v1_sha256_2491fff4ad0327e0440d842f221fb6623c8efd97e2991bf2090abceaef9c2ccf"
        version = "1.0"
        date = "2022-12-16"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Strings found in the Zerobot Spoofed Header method"
        category = "INFO"
        threat_name = "Linux.Trojan.Zerobot"
        reference_sample = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $HootSpoofHeader_0 = "X-Forwarded-Proto: Http"
        $HootSpoofHeader_1 = "X-Forwarded-Host: %s, 1.1.1.1"
        $HootSpoofHeader_2 = "Client-IP: %s"
        $HootSpoofHeader_3 = "Real-IP: %s"
        $HootSpoofHeader_4 = "X-Forwarded-For: %s"
    condition:
        3 of them
}

