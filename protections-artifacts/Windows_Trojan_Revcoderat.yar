rule Windows_Trojan_Revcoderat_8e6d4182 {
    meta:
        id = "5CzW6ue2CULIPGbbKjxsjp"
        fingerprint = "v1_sha256_35626d752b291e343350534aece35f1d875068c2c050d12312a60e67753c71e1"
        version = "1.0"
        date = "2021-09-02"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Revcoderat"
        reference_sample = "77732e74850050bb6f935945e510d32a0499d820fa1197752df8bd01c66e8210"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "PLUGIN_PROCESS_REVERSE_PROXY: Plugin already exists, skipping download!" ascii fullword
        $a2 = "TARGET_HOST_UPDATE(): Sync successful!" ascii fullword
        $a3 = "WEBCAM_ACTIVATE: Plugin already exists, skipping download!" ascii fullword
        $a4 = "send_keylog_get" ascii fullword
    condition:
        all of them
}

