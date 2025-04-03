rule Windows_Trojan_Hawkeye_77c36ace {
    meta:
        id = "20mMOCuqCt3bNJ1utRQctc"
        fingerprint = "v1_sha256_e8c1060efde0c4a073247d03a19dedb1c0acc8506fbf6eac93ac44f00fc73be1"
        version = "1.0"
        date = "2021-08-16"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Hawkeye"
        reference_sample = "28e28025060f1bafd4eb96c7477cab73497ca2144b52e664b254c616607d94cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Logger - Key Recorder - [" wide fullword
        $a2 = "http://whatismyipaddress.com/" wide fullword
        $a3 = "Keylogger Enabled: " wide fullword
        $a4 = "LoadPasswordsSeaMonkey" wide fullword
        $a5 = "\\.minecraft\\lastlogin" wide fullword
    condition:
        all of them
}

rule Windows_Trojan_Hawkeye_975d546c {
    meta:
        id = "8epwpZRjL8F1OHrSn0Kff"
        fingerprint = "v1_sha256_cbd8ce991059f961236a4bb83ea5a78efa661199b40fca8b09550856e932198b"
        version = "1.0"
        date = "2023-03-23"
        modified = "2023-04-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Hawkeye"
        reference_sample = "aca133bf1d72cf379101e6877871979d6e6e8bc4cc692a5ba815289735014340"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "api.telegram.org"
        $s2 = "Browsers/Passwords"
        $s3 = "Installed Browsers.txt"
        $s4 = "Browsers/AutoFills"
        $s5 = "Passwords.txt"
        $s6 = "System Information.txt"
    condition:
        all of them
}

