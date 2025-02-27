rule Windows_Ransomware_Ransomexx_fabff49c {
    meta:
        id = "1x5iINlhK64WZa0cpqahPp"
        fingerprint = "v1_sha256_67d5123b706685ea5ab939aec31cb1549297778d91dd38b14e109945c52da71a"
        version = "1.0"
        date = "2021-08-07"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Ransomexx"
        reference_sample = "480af18104198ad3db1518501ee58f9c4aecd19dbbf2c5dd7694d1d87e9aeac7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "ransom.exx" ascii fullword
        $a2 = "Infrastructure rebuild will cost you MUCH more." wide fullword
        $a3 = "Your files are securely ENCRYPTED." wide fullword
        $a4 = "delete catalog -quiet" wide fullword
    condition:
        all of them
}

