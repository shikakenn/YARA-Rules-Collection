rule Windows_Ransomware_Medusa_fda487fd {
    meta:
        id = "46aoyqxC7lFW8Km9HzEblp"
        fingerprint = "v1_sha256_12223e8b6f5b88ddf95f01e5c2a6e2dc96ab79eb3a5a4e0582b55244ee77b36a"
        version = "1.0"
        date = "2025-02-04"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Medusa"
        reference_sample = "3a6d5694eec724726efa3327a50fad3efdc623c08d647b51e51cd578bddda3da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "kill_processes %s" ascii fullword
        $a2 = "kill_services %s" ascii fullword
        $a3 = ":note path = %s" ascii fullword
        $a4 = "Write Note file error:%s" ascii fullword
        $a5 = "Rename file error:%s" ascii fullword
        $a6 = "G:\\Medusa\\Release\\gaze.pdb" ascii fullword
    condition:
        5 of them
}

