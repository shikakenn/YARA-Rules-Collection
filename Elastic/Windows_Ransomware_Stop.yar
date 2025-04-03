rule Windows_Ransomware_Stop_1e8d48ff {
    meta:
        id = "5YxT7rY2sQAb474qSTBqQ"
        fingerprint = "v1_sha256_d743feae072a5f3e1b008354352bef48218bb041bc8a5ba39526815ab9cd2690"
        version = "1.0"
        date = "2021-06-10"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Stop"
        reference_sample = "821b27488f296e15542b13ac162db4a354cbf4386b6cd40a550c4a71f4d628f3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = "E:\\Doc\\My work (C++)\\_Git\\Encryption\\Release\\encrypt_win_api.pdb" ascii fullword
        $b = { 68 FF FF FF 50 FF D3 8D 85 78 FF FF FF 50 FF D3 8D 85 58 FF }
    condition:
        any of them
}

