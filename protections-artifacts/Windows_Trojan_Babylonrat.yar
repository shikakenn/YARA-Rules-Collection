rule Windows_Trojan_Babylonrat_0f66e73b {
    meta:
        id = "64wkzpeFJQyCmuvsGS09mP"
        fingerprint = "v1_sha256_66223dc9e2ef7330e26c91f0c82c555e96e4c794a637ab2cbe36410f3eca202a"
        version = "1.0"
        date = "2021-09-02"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Babylonrat"
        reference_sample = "4278064ec50f87bb0471053c068b13955ed9d599434e687a64bf2060438a7511"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "BabylonRAT" wide fullword
        $a2 = "Babylon RAT Client" wide fullword
        $a3 = "ping 0 & del \"" wide fullword
        $a4 = "\\%Y %m %d - %I %M %p" wide fullword
    condition:
        all of them
}

