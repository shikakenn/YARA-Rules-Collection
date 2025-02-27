rule Linux_Trojan_Bedevil_a1a72c39 {
    meta:
        id = "2KoZiN50Ju5tP7AzfyFoEm"
        fingerprint = "v1_sha256_227adcc340c38cebf56ea2f39b483c965dd46827d83afe5f866ca844c932da76"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Bedevil"
        reference_sample = "017a9d7290cf327444d23227518ab612111ca148da7225e64a9f6ebd253449ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 73 3A 20 1B 5B 31 3B 33 31 6D 25 64 1B 5B 30 6D 0A 00 1B 5B }
    condition:
        all of them
}

