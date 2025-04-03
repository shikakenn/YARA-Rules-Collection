rule GhostWriter_MicroBackdoor_72632_00001 {
    meta:
        id = "7FGHfqrLVfZ0jjmDxceO1m"
        fingerprint = "v1_sha256_cb58d374036f0e52299adb2c7b6795a3610e9d3b29be041d4aa32b44b19a1680"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cluster25"
        description = "NA"
        category = "INFO"
        report = "HTTPS://BLOG.CLUSTER25.DUSKRISE.COM/2022/03/08/GHOSTWRITER-UNC1151-ADOPTS-MICROBACKDOOR-VARIANTS-IN-CYBER-OPERATIONS-AGAINST-TARGETS-IN-UKRAINE"
        hash1 = "559d8e8f2c60478d1c057b46ec6be912fae7df38e89553804cc566cac46e8e91"
        tlp = "white"

strings:
$ = "cmd.exe /C \"%s%s\"" fullword wide
$ = "client.dll" fullword ascii
$ = "ERROR: Unknown command" fullword ascii
$ = " *** ERROR: Timeout occured" fullword ascii
$ = "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
$ = "MIIDazCCAlOgAwIBAgIUWOftflCclQXpmWMnL1ewj2F5Y1AwDQYJKoZIhvcNAQEL" fullword ascii
condition: (uint16(0) == 0x5a4d and all of them)
}
