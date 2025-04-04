rule Windows_Trojan_Nanocore_d8c4e3c5 {
    meta:
        id = "2vNnwbRLAe8NyRI9cFkQGs"
        fingerprint = "v1_sha256_fcc13e834cd8a1f86b453fe3c0333cd358e129d6838a339a824f1a095d85552d"
        version = "1.0"
        date = "2021-06-13"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Nanocore"
        reference_sample = "b2262126a955e306dc68487333394dc08c4fbd708a19afeb531f58916ddb1cfd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "NanoCore.ClientPluginHost" ascii fullword
        $a2 = "NanoCore.ClientPlugin" ascii fullword
        $b1 = "get_BuilderSettings" ascii fullword
        $b2 = "ClientLoaderForm.resources" ascii fullword
        $b3 = "PluginCommand" ascii fullword
        $b4 = "IClientAppHost" ascii fullword
        $b5 = "GetBlockHash" ascii fullword
        $b6 = "AddHostEntry" ascii fullword
        $b7 = "LogClientException" ascii fullword
        $b8 = "PipeExists" ascii fullword
        $b9 = "IClientLoggingHost" ascii fullword
    condition:
        1 of ($a*) or 6 of ($b*)
}

