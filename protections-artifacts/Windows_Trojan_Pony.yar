rule Windows_Trojan_Pony_d5516fe8 {
    meta:
        id = "6y8D53JVWidpL6xjYUhWaY"
        fingerprint = "v1_sha256_4a850d32fb28477e7e3fef2dda6ba327b800e2ebcae1a483970cde78f34a4ff7"
        version = "1.0"
        date = "2021-08-14"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Pony"
        reference_sample = "423e792fcd00265960877482e8148a0d49f0898f4bbc190894721fde22638567"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\Global Downloader" ascii fullword
        $a2 = "wiseftpsrvs.bin" ascii fullword
        $a3 = "SiteServer %d\\SFTP" ascii fullword
        $a4 = "%s\\Keychain" ascii fullword
        $a5 = "Connections.txt" ascii fullword
        $a6 = "ftpshell.fsi" ascii fullword
        $a7 = "inetcomm server passwords" ascii fullword
    condition:
        all of them
}

