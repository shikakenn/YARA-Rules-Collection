rule Linux_Ransomware_Sodinokibi_2883d7cd {
    meta:
        id = "EVUslyN9ixknmmb7R8nFQ"
        fingerprint = "v1_sha256_97d6b1b641c4b5b596b67a809e8e70bb0bccb9219282cd6c41bc905e2ea44c84"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Sodinokibi"
        reference_sample = "a322b230a3451fd11dcfe72af4da1df07183d6aaf1ab9e062f0e6b14cf6d23cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 85 08 FF FF FF 48 01 85 28 FF FF FF 48 8B 85 08 FF FF FF 48 29 85 20 FF }
    condition:
        all of them
}

