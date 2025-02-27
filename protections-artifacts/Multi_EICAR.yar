rule Multi_EICAR_ac8f42d6 {
    meta:
        id = "1okTnYeqUqxfQFywUVq3rz"
        fingerprint = "v1_sha256_05c92058aab1229dfa31e006276c2c83fa484e813bdfe66edf387763797d9d57"
        version = "1.0"
        date = "2021-01-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.EICAR.Not-a-virus"
        severity = 1
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword
    condition:
        all of them
}

