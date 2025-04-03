rule Linux_Trojan_DinodasRAT_1d371d10 {
    meta:
        id = "40VxyO2zbxRs1wvjhgNdW4"
        fingerprint = "v1_sha256_933e78882be1d8dd9553ba90f038963d1b6f8f643888258541b7668aa3434808"
        version = "1.0"
        date = "2024-04-02"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.DinodasRAT"
        reference_sample = "bf830191215e0c8db207ea320d8e795990cf6b3e6698932e6e0c9c0588fc9eff"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $s1 = "int MyShell::createsh()"
        $s2 = "/src/myshell.cpp"
        $s3 = "/src/inifile.cpp"
        $s4 = "Linux_%s_%s_%u_V"
        $s5 = "/home/soft/mm/rootkit/"
        $s6 = "IniFile::load_ini_file"
    condition:
        4 of them
}

