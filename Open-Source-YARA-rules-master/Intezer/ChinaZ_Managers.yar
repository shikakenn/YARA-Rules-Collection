private rule NewManager {
    meta:
        id = "1AcyT3bb963nOxcukMMvna"
        fingerprint = "v1_sha256_cdc955b0cdd6a2b0db1f9ad51ed4ea4f8cf98d5730a6c39d83e1739e157a4cec"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
        $a0 = {8B ?? 04 3? 03 00 00 11 74 4D 3? 11 00 00 11 74 61 3? 02 00 00 11 } 
        $b0 = "_ConnectServer"
        $b1 = "/root/1/ampS.log"
        $b2 = "/etc/rc%d.d/S%d%s"
        $b3 = "Get SYstem Info"
        $b4 = "newmanager"
        $b5 = "NO DDXC"

    condition:
        all of them
}

private rule AmpManager {
    meta:
        id = "chR2o7aBnw1soyIS17wYj"
        fingerprint = "v1_sha256_6d435538b5739cf24c5244477a031b69fc9f764ee94dd7b974fd4cd0201d04d8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
        $a0 = {C7 85 ?? F8 FF FF ?? 00 00 11 C7 85 ?? F8 FF FF 00 00 00 00 C7 85 ?? F8 FF FF ?? 00 00 00} 
        $b0 = "ampserver/main.cpp"
        $b1 = "M-SEARCH * HTTP/1.1"
        $b2 = "rm -f /usr/bin/ammint | killall ammint 2>/dev/null &"
        $b3 = "ln -s /etc/init.d/%s %s"
        $b4 = "camplz123"

    condition:
        all of them
}

private rule DDoSManager { 
    meta:
        id = "56tzcTXkwhkIYO2yLDD6Oy"
        fingerprint = "v1_sha256_289354a42739f0a18c469b2fa08ccf75cc76a2bf17f64fbc17ec0495f41a47b3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
        $a0 = { 55 89 e5 5? 8b ?? 0c 8B ?? 08 85 ?? 7E 16 31 ?? 0F B6 ?? ?? 83 F? 19 83 C? 7A 88 ?? ?? 83 C? 01} 
        $b0 = "5CFake"
        $b1 = "/tmp/Cfg.9"
        $b2 = "0|%s|%s|1|65535|"
        $b3 = "8CManager"
        $b4 = "SingTool"

    condition:
        all of them
}

rule ChinaZ_Managers {
    meta:
        id = "7bBomme3Wmbx2KYYeFge6"
        fingerprint = "v1_sha256_da5a4826482cb1bd2b658fb69ea7e11d950f681511c3c757b28f0c387de21897"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    condition:
        NewManager or AmpManager or DDoSManager
}
