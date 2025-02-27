rule Windows_Ransomware_Lockfile_74185716 {
    meta:
        id = "3NRbXgVwufKP7Vx1RJT3yv"
        fingerprint = "v1_sha256_e922c2fc9dd52dd0238847a9d48691bea90d028cf680fc3a1a0dbdfef1d8dce3"
        version = "1.0"
        date = "2021-08-31"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Lockfile"
        reference_sample = "bf315c9c064b887ee3276e1342d43637d8c0e067260946db45942f39b970d7ce"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "LOCKFILE-README"
        $a2 = "wmic process where \"name  like '%virtualbox%'\" call terminate"
        $a3 = "</computername>"
        $a4 = ".lockfile"
    condition:
        all of them
}

