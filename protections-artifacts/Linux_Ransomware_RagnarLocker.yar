rule Linux_Ransomware_RagnarLocker_9f5982b8 {
    meta:
        id = "3f3dNJXEK6gYRyY71HrzlD"
        fingerprint = "v1_sha256_c08579dc675a709add392a0189d01e05af61034b72f451d2b024c89c1299ee6c"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.RagnarLocker"
        reference_sample = "f668f74d8808f5658153ff3e6aee8653b6324ada70a4aa2034dfa20d96875836"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = ".README_TO_RESTORE"
        $a2 = "If WE MAKE A DEAL:"
        $a3 = "Unable to rename file from: %s to: %s"
    condition:
        2 of them
}

