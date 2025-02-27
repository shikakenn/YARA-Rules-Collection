rule Windows_Ransomware_Conti_89f3f6fa {
    meta:
        id = "34sTF3kWifdefadmtLxQnA"
        fingerprint = "v1_sha256_4c1834e45d5e42f466249b75a89561ce1e88b9e3c07070e2833d4897fbed22ee"
        version = "1.0"
        date = "2021-08-05"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Conti"
        reference_sample = "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { F7 FE 88 57 FF 83 EB 01 75 DA 8B 45 FC 5F 5B 40 5E 8B E5 5D C3 8D }
    condition:
        all of them
}

