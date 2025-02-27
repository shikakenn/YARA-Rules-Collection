rule Linux_Hacktool_Infectionmonkey_6c84537b {
    meta:
        id = "7AYmI1H94B4l7S7JHHXEEG"
        fingerprint = "v1_sha256_24cb368040fffe2743d0361a955d45a62a95a31c1744f3de15089169e365bb89"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Infectionmonkey"
        reference_sample = "d941943046db48cf0eb7f11e144a79749848ae6b50014833c5390936e829f6c3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 75 14 8B 54 24 0C 83 FA FF 0F 44 D0 83 C4 1C 89 D0 C3 8D 74 }
    condition:
        all of them
}

