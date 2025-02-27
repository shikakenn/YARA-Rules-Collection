rule MacOS_Trojan_Electrorat_b4dbfd1d {
    meta:
        id = "42gGTni1HP5OAsHdDTRg4P"
        fingerprint = "v1_sha256_a36143a8c93cb187dba0a88a15550219c19f1483502f782dfefc1e53829cfbf1"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Electrorat"
        reference_sample = "b1028b38fcce0d54f2013c89a9c0605ccb316c36c27faf3a35adf435837025a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = "_TtC9Keylogger9Keylogger" ascii fullword
        $a2 = "_TtC9Keylogger17CallBackFunctions" ascii fullword
        $a3 = "\\DELETE-FORWARD" ascii fullword
        $a4 = "\\CAPSLOCK" ascii fullword
    condition:
        all of them
}

