rule Linux_Ransomware_LimpDemon_95c748e0 {
    meta:
        id = "3eP5S0k3VmfiqCHOzZW0fp"
        fingerprint = "v1_sha256_e66906725c0af657d91771642908ac0b2c72a97c4d4f651dcc907c2c1437f2da"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.LimpDemon"
        reference_sample = "a4200e90a821a2f2eb3056872f06cf5b057be154dcc410274955b2aaca831651"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "[-] You have to pass access key to start process" fullword
        $a2 = "[+] Shutting down VMWare ESXi servers..." fullword
        $a3 = "%s --daemon (start as a service)" fullword
        $a4 = "%s --access-key <key> (key for decryption config)" fullword
    condition:
        2 of them
}

