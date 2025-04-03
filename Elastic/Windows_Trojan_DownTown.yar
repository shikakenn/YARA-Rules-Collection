rule Windows_Trojan_DownTown_901c4fdd {
    meta:
        id = "6Y7jWlcmcrZyaxzWKiObUC"
        fingerprint = "v1_sha256_6368d37fa9ba4e32131e16bceaee322f2fa8507873d01ebd687536e593354725"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        threat_name = "Windows.Trojan.DownTown"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "SendFileBuffer error -1 !!!" fullword
        $a2 = "ScheduledDownloadTasks CODE_FILE_VIEW " fullword
        $a3 = "ExplorerManagerC.dll" fullword
    condition:
        3 of them
}

rule Windows_Trojan_DownTown_145ecd2f {
    meta:
        id = "iEiHwcTmkZ4oDzunr4fge"
        fingerprint = "v1_sha256_744a51c5317e265177185d9d0b8838a8fc939b4c56cc5e5bc51d5432d046d9f1"
        version = "1.0"
        date = "2023-08-23"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        threat_name = "Windows.Trojan.DownTown"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "DeletePluginObject"
        $a2 = "GetPluginInfomation"
        $a3 = "GetPluginObject"
        $a4 = "GetRegisterCode"
    condition:
        all of them
}

