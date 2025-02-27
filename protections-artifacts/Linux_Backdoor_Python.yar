rule Linux_Backdoor_Python_00606bac {
    meta:
        id = "6WybRCl6JnNR1vTCYGBvoc"
        fingerprint = "v1_sha256_92ad2cf4aa848c8f3bcedd319654bf5ef873cd4daba62572381c7e20f0296b82"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Backdoor.Python"
        reference_sample = "b3e3728d43535f47a1c15b915c2d29835d9769a9dc69eb1b16e40d5ba1b98460"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F4 01 83 45 F8 01 8B 45 F8 0F B6 00 84 C0 75 F2 83 45 F8 01 8B }
    condition:
        all of them
}

