rule Linux_Ransomware_Clop_728cf32a {
    meta:
        id = "5XEUaqLybSJoogXN4sojn"
        fingerprint = "v1_sha256_31c2fdfcfc46ad1dd69489536172937b9771d8505f36c7bd8dc796f40a2fe4d2"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Clop"
        reference_sample = "09d6dab9b70a74f61c41eaa485b37de9a40c86b6d2eae7413db11b4e6a8256ef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "CONTACT US BY EMAIL:"
        $a2 = "OR WRITE TO THE CHAT AT->"
        $a3 = "(use TOR browser)"
        $a4 = ".onion/"
    condition:
        3 of them
}

