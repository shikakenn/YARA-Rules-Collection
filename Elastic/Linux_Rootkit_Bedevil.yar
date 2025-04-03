rule Linux_Rootkit_Bedevil_2af79cea {
    meta:
        id = "4P6oi6yeZtAoHziiBGjPss"
        fingerprint = "v1_sha256_3acded46df45f88cf2cdd0eab424810d3dab51cac90845574a1361301e72be23"
        version = "1.0"
        date = "2024-11-14"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Bedevil"
        reference_sample = "8f8c598350632b32e72cd6af3a0ca93c05b4d9100fd03e2ae1aec97a946eb347"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "bdvinstall"
        $str2 = "putbdvlenv"
        $str3 = "bdvprep"
        $str4 = "bdvcleanse"
        $str5 = "dobdvutil"
        $str6 = "forge_maps"
        $str7 = "forge_smaps"
        $str8 = "forge_numamaps"
        $str9 = "forge_procnet"
        $str10 = "secret_connection"
        $str11 = "dropshell"
    condition:
        4 of ($str*)
}

