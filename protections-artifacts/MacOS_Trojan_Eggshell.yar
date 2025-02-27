rule MacOS_Trojan_Eggshell_ddacf7b9 {
    meta:
        id = "4s767RVdEAlDHigcBiiNwc"
        fingerprint = "v1_sha256_f986f7d1e3a68e27f82048017c6d6381a0354ffad2cd10f3eee69bbbfa940abd"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Eggshell"
        reference_sample = "6d93a714dd008746569c0fbd00fadccbd5f15eef06b200a4e831df0dc8f3d05b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = "ScreenshotThread" ascii fullword
        $a2 = "KeylogThread" ascii fullword
        $a3 = "GetClipboardThread" ascii fullword
        $a4 = "_uploadProgress" ascii fullword
        $a5 = "killTask:" ascii fullword
    condition:
        all of them
}

