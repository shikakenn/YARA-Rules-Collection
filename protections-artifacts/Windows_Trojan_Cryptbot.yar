rule Windows_Trojan_Cryptbot_489a6562 {
    meta:
        id = "7mWGl0cG0lU74DMXcBeHGU"
        fingerprint = "v1_sha256_7fee3cc67419e66de790ba2ad8c3102425b3a45bdfe31801758dd38021a8439b"
        version = "1.0"
        date = "2021-08-18"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Cryptbot"
        reference_sample = "423563995910af04cb2c4136bf50607fc26977dfa043a84433e8bd64b3315110"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "/c rd /s /q %Temp%\\" wide fullword
        $a2 = "\\_Files\\_AllPasswords_list.txt" wide fullword
        $a3 = "\\files_\\cryptocurrency\\log.txt" wide fullword
        $a4 = "%wS\\%wS\\%wS.tmp" wide fullword
        $a5 = "%AppData%\\waves-exchange" wide fullword
    condition:
        all of them
}

