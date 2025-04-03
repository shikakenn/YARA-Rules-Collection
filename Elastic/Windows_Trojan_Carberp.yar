rule Windows_Trojan_Carberp_d6de82ae {
    meta:
        id = "4LdHTDQy8lzsh8X2YGLVg"
        fingerprint = "v1_sha256_085020755c77b299b2bfd18b34af6c68450c29de67b8ae32ddf2b26299b923ae"
        version = "1.0"
        date = "2021-02-07"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies VNC module from the leaked Carberp source code. This could exist in other malware families."
        category = "INFO"
        reference = "https://github.com/m0n0ph1/malware-1/blob/master/Carberp%20Botnet/source%20-%20absource/pro/all%20source/hvnc_dll/HVNC%20Lib/vnc/xvnc.h#L342"
        threat_name = "Windows.Trojan.Carberp"
        reference_sample = "f98fadb6feab71930bd5c08e85153898d686cc96c84fe349c00bf6d482de9b53"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = ".NET CLR Networking_Perf_Library_Lock_PID_0" ascii wide fullword
        $a2 = "FakeVNCWnd" ascii wide fullword
    condition:
        all of them
}

