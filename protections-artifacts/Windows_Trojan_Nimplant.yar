rule Windows_Trojan_Nimplant_44ff3211 {
    meta:
        id = "5YMZkkrcQDsfbmOgz5X7QT"
        fingerprint = "v1_sha256_ee519d8d722404ed440b385d283a41921bc34ee11f0e7273cdc074b377494c39"
        version = "1.0"
        date = "2023-06-23"
        modified = "2023-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Nimplant"
        reference_sample = "b56e20384f98e1d2417bb7dcdbfb375987dd075911b74ea7ead082494836b8f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "@NimPlant v"
        $a2 = ".Env_NimPlant."
        $a3 = "NimPlant.dll"
    condition:
        2 of them
}

