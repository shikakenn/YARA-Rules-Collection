rule Windows_Trojan_AgentTesla_d3ac2b2f {
    meta:
        id = "1598n4fe1KqvTz61jXwCN1"
        fingerprint = "v1_sha256_9c13a99107593d476de1522ced10aa43d34535b844e8c3ae871b22358137c926"
        version = "1.0"
        date = "2021-03-22"
        modified = "2022-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        threat_name = "Windows.Trojan.AgentTesla"
        reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "GetMozillaFromLogins" ascii fullword
        $a2 = "AccountConfiguration+username" wide fullword
        $a3 = "MailAccountConfiguration" ascii fullword
        $a4 = "KillTorProcess" ascii fullword
        $a5 = "SmtpAccountConfiguration" ascii fullword
        $a6 = "GetMozillaFromSQLite" ascii fullword
        $a7 = "Proxy-Agent: HToS5x" wide fullword
        $a8 = "set_BindingAccountConfiguration" ascii fullword
        $a9 = "doUsernamePasswordAuth" ascii fullword
        $a10 = "SafariDecryptor" ascii fullword
        $a11 = "get_securityProfile" ascii fullword
        $a12 = "get_useSeparateFolderTree" ascii fullword
        $a13 = "get_DnsResolver" ascii fullword
        $a14 = "get_archivingScope" ascii fullword
        $a15 = "get_providerName" ascii fullword
        $a16 = "get_ClipboardHook" ascii fullword
        $a17 = "get_priority" ascii fullword
        $a18 = "get_advancedParameters" ascii fullword
        $a19 = "get_disabledByRestriction" ascii fullword
        $a20 = "get_LastAccessed" ascii fullword
        $a21 = "get_avatarType" ascii fullword
        $a22 = "get_signaturePresets" ascii fullword
        $a23 = "get_enableLog" ascii fullword
        $a24 = "TelegramLog" ascii fullword
        $a25 = "generateKeyV75" ascii fullword
        $a26 = "set_accountName" ascii fullword
        $a27 = "set_InternalServerPort" ascii fullword
        $a28 = "set_bindingConfigurationUID" ascii fullword
        $a29 = "set_IdnAddress" ascii fullword
        $a30 = "set_GuidMasterKey" ascii fullword
        $a31 = "set_username" ascii fullword
        $a32 = "set_version" ascii fullword
        $a33 = "get_Clipboard" ascii fullword
        $a34 = "get_Keyboard" ascii fullword
        $a35 = "get_ShiftKeyDown" ascii fullword
        $a36 = "get_AltKeyDown" ascii fullword
        $a37 = "get_Password" ascii fullword
        $a38 = "get_PasswordHash" ascii fullword
        $a39 = "get_DefaultCredentials" ascii fullword
    condition:
        8 of ($a*)
}

rule Windows_Trojan_AgentTesla_e577e17e {
    meta:
        id = "3VyKQFGbcGnWkm7UYpYxk7"
        fingerprint = "v1_sha256_84c5f1096735cee0f0f4ad41a81286c0a60dc17c276f23568b855271d996c8a2"
        version = "1.0"
        date = "2022-03-11"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        threat_name = "Windows.Trojan.AgentTesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_f2a90d14 {
    meta:
        id = "5drnrURlcD9kyyXCiIeXge"
        fingerprint = "v1_sha256_3f39b773f2b1524b05d3c1d9aa1fb54594ec9003d2e9da342b6d17ba885f5a03"
        version = "1.0"
        date = "2022-03-11"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        threat_name = "Windows.Trojan.AgentTesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_a2d69e48 {
    meta:
        id = "vFDvOBy8i4ULRU74fs1rs"
        fingerprint = "v1_sha256_1f90be86b7afa7f518a3dcec55028bfc915cf6d4fed1350a56e351946cc55f41"
        version = "1.0"
        date = "2023-05-01"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        threat_name = "Windows.Trojan.AgentTesla"
        reference_sample = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
        $a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_ebf431a8 {
    meta:
        id = "2EBKKOGnYuVmnORJUZ2wzN"
        fingerprint = "v1_sha256_b02d6e2d68b336aaa37336e0c0c3ffa6c7a126bfcdb6cb6ad5a3432004c6030c"
        version = "1.0"
        date = "2023-12-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        threat_name = "Windows.Trojan.AgentTesla"
        reference_sample = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "MozillaBrowserList"
        $a2 = "EnableScreenLogger"
        $a3 = "VaultGetItem_WIN7"
        $a4 = "PublicIpAddressGrab"
        $a5 = "EnableTorPanel"
        $a6 = "get_GuidMasterKey"
    condition:
        4 of them
}

