rule Linux_Rootkit_HiddenWasp_8408057b {
    meta:
        id = "2EW0G6UdXnzrMiwGqn3Pe5"
        fingerprint = "v1_sha256_1d21cdd38d7428c498eface37fb8b1ca1e99295c88f57cb638871753d0be0f15"
        version = "1.0"
        date = "2024-11-14"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.HiddenWasp"
        reference_sample = "7c5e20872bc0ac5cce83d4c68485743cd16a818cd1e495f97438caad0399c847"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "HIDE_THIS_SHELL"
        $str2 = "I_AM_HIDDEN"
        $func1 = "hiding_hideproc"
        $func2 = "hiding_unhidefile"
        $func3 = "hiding_hidefile"
        $func4 = "hiding_unhideproc"
        $func5 = "/proc/hide-%d"
        $func6 = "hiding_disable_logging"
        $func7 = "hiding_init"
        $func8 = "hiding_uninstall"
        $func9 = "hiding_removeproc"
        $func10 = "hiding_makeroot"
        $func11 = "hiding_free"
        $func12 = "hiding_enable_logging"
        $func13 = "hiding_getvers"
        $func14 = "hidden_services"
    condition:
        all of ($str*) or 5 of ($func*)
}

