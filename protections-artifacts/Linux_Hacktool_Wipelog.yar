rule Linux_Hacktool_Wipelog_daea1aa4 {
    meta:
        id = "7i0j85JMXIi4yiL03ZqjYy"
        fingerprint = "v1_sha256_e2483b7719f4a1e28ec3732120770066333d8db269c9c9711813a8eeb75176d6"
        version = "1.0"
        date = "2022-03-17"
        modified = "2022-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Wipelog"
        reference_sample = "39b3a95928326012c3b2f64e2663663adde4b028d940c7e804ac4d3953677ea6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $s1 = "Erase one username on tty"
        $s2 = "wipe_utmp"
        $s3 = "wipe_acct"
        $s4 = "wipe_lastlog"
        $s5 = "wipe_wtmp"
        $s6 = "getpwnam"
        $s7 = "ERROR: Can't find user in passwd"
        $s8 = "ERROR: Opening tmp ACCT file"
        $s9 = "/var/log/wtmp"
        $s10 = "/var/log/lastlog"
        $s11 = "Patching %s ...."
    condition:
        4 of them
}

