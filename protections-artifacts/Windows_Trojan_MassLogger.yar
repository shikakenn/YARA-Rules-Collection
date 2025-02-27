rule Windows_Trojan_MassLogger_511b001e {
    meta:
        id = "PlYlnicB1XLXt9cEmMyDD"
        fingerprint = "v1_sha256_5abac5e32e55467710842e19c25cab5c7f1cdb0f8a68fb6808d54467c69ebdf6"
        version = "1.0"
        date = "2022-03-02"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.MassLogger"
        reference_sample = "177875c756a494872c516000beb6011cec22bd9a73e58ba6b2371dba2ab8c337"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "ExecutionPolicy Bypass -WindowStyle Hidden -Command netsh advfirewall firewall add rule name='allow RemoteDesktop' dir=in protoc" wide
        $a2 = "https://raw.githubusercontent.com/lisence-system/assemply/main/VMprotectEncrypt.jpg" wide fullword
        $a3 = "ECHO $SMTPServer  = smtp.gmail.com >> %PSScript%" wide fullword
        $a4 = "Injecting Default Template...." wide fullword
        $a5 = "GetVncLoginMethodAsync" ascii fullword
        $a6 = "/c start computerdefaults.exe" wide fullword
    condition:
        all of them
}

