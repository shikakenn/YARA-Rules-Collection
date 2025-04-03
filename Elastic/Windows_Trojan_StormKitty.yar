rule Windows_Trojan_StormKitty_6256031a {
    meta:
        id = "4nWdwZ0EINPpGppYNBa39W"
        fingerprint = "v1_sha256_a797e87eaf5b173da9dd43fcff03b3d26198dcafa29c3f2ca369773c73001234"
        version = "1.0"
        date = "2022-03-21"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.StormKitty"
        reference_sample = "0c69015f534d1da3770dbc14183474a643c4332de6a599278832abd2b15ba027"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "https://github.com/LimerBoy/StormKitty" ascii fullword
        $a2 = "127.0.0.1 www.malwarebytes.com" wide fullword
        $a3 = "KillDefender"
        $a4 = "Username: {1}" wide fullword
        $a5 = "# End of Cookies" wide fullword
        $a6 = "# End of Passwords" wide fullword
    condition:
        all of them
}

