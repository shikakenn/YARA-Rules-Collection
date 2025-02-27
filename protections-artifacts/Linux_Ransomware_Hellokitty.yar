rule Linux_Ransomware_Hellokitty_35731270 {
    meta:
        id = "68EL9Yl1e4KOiacWnvkDNz"
        fingerprint = "v1_sha256_40cb632d6b8561de56f2010a082a24b0c50d4cabed21e073168b5302ddff7044"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Hellokitty"
        reference_sample = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "File Locked:%s PID:%d" fullword
        $a2 = "error encrypt: %s rename back:%s" fullword
        $a3 = "esxcli vm process kill -t=soft -w=%d" fullword
    condition:
        2 of them
}

