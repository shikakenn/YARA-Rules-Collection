rule Windows_Hacktool_ClrOxide_d92d9575 {
    meta:
        id = "51wKWnruWtUw6nN6KwmfFt"
        fingerprint = "v1_sha256_01bb071e1286bb139c5e1c37e421153ef1b28a5994feeaedf6ad27ad7dade5e9"
        version = "1.0"
        date = "2024-02-29"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.ClrOxide"
        reference_sample = "f3a4900eff80563bff586ced172c3988347980f902aceef2f9f9f6d188fac8e3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "clroxide..primitives..imethodinfo"
        $s2 = "clroxide..clr..Clr"
        $s3 = "\\src\\primitives\\icorruntimehost.rs"
        $s4 = "\\src\\primitives\\iclrruntimeinfo.rs"
        $s5 = "\\src\\primitives\\iclrmetahost.rs"
        $s6 = "clroxide\\src\\clr\\mod.rs"
        $s7 = "__clrcall"
    condition:
        2 of them
}

