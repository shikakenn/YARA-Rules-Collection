rule Linux_Hacktool_Fontonlake_68ad8568 {
    meta:
        id = "6O6GJXXMiHHBZyHoKDvytI"
        fingerprint = "v1_sha256_63dd5769305c715e27e3c62160f7b0f65b57204009ed46383b5b477c67cfac8e"
        version = "1.0"
        date = "2021-10-12"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Fontonlake"
        reference_sample = "717953f52318e7687fc95626561cc607d4875d77ff7e3cf5c7b21cf91f576fa4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $s1 = "run_in_bash"
        $s2 = "run_in_ss"
        $s3 = "real_bash_fork"
        $s4 = "fake_bash_add_history"
        $s5 = "hook_bash_add_history"
        $s6 = "real_bash_add_history"
        $s7 = "real_current_user.5417"
        $s8 = "real_bash_execve"
        $s9 = "inject_so_symbol.c"
        $s10 = "/root/rmgr_ko/subhook-0.5/subhook_x86.c"
        $s11 = "|1|%ld|%d|%d|%d|%d|%s|%s"
        $s12 = "/proc/.dot3"
    condition:
        4 of them
}

