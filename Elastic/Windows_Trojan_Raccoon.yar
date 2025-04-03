rule Windows_Trojan_Raccoon_af6decc6 {
    meta:
        id = "mnqCVFtSbytTEFVQBzz9I"
        fingerprint = "v1_sha256_50ec446e8fd51129c7333c943dfe62db099fe1379530441f6b102fcbe3bc0dbd"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Raccoon"
        reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "A:\\_Work\\rc-build-v1-exe\\json.hpp" wide fullword
        $a2 = "\\stealler\\json.hpp" wide fullword
    condition:
        any of them
}

rule Windows_Trojan_Raccoon_58091f64 {
    meta:
        id = "6F0FUZrb93wj8IRmH6vmUc"
        fingerprint = "v1_sha256_8a7388e9c3dd0dd1a79215dbabcd964a0afa883490611afb6bb500635fbfff9a"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Raccoon"
        reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 74 FF FF FF 10 8D 4D AC 53 6A 01 8D 85 60 FF FF FF 0F 43 85 60 FF }
    condition:
        all of them
}

rule Windows_Trojan_Raccoon_deb6325c {
    meta:
        id = "1zi722DaS8pDp16wp8Jgpq"
        fingerprint = "v1_sha256_94f70c60ed4fab021e013cf6a632321e0e1bdeef25a48a598d9e7388e7e445ca"
        version = "1.0"
        date = "2022-06-28"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Raccoon"
        reference_sample = "f7b1aaae018d5287444990606fc43a0f2deb4ac0c7b2712cc28331781d43ae27"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\ffcookies.txt" wide fullword
        $a2 = "wallet.dat" wide fullword
        $a3 = "0Network\\Cookies" wide fullword
        $a4 = "Wn0nlDEXjIzjLlkEHYxNvTAXHXRteWg0ieGKVyD52CvONbW7G91RvQDwSZi/N2ISm4xEWRKYJwjnYUGS9OZmj/TAie8jG07EXEcO8D7h2m2lGzWnFG31R1rsxG1+G8E="
    condition:
        all of them
}

