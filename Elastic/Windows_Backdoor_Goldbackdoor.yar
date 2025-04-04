rule Windows_Backdoor_Goldbackdoor_91902940 {
    meta:
        id = "3zV674idB4G0LFr3hebySM"
        fingerprint = "v1_sha256_71e26cce6d730560e1303b2a4f49d0da6d1341263bb47ade46338f03e528cbf7"
        version = "1.0"
        date = "2022-04-29"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Backdoor.Goldbackdoor"
        reference_sample = "485246b411ef5ea9e903397a5490d106946a8323aaf79e6041bdf94763a0c028"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $pdf = "D:\\Development\\GOLD-BACKDOOR\\"
        $agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.3112.113 Safari/537.36"
        $str0 = "client_id"
        $str1 = "client_secret"
        $str2 = "redirect_uri"
        $str3 = "refresh_token"
        $a = { 56 57 8B 7D 08 8B F1 6A 00 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 46 30 85 C0 75 ?? 33 C0 5F 5E }
        $b = { 66 8B 02 83 C2 02 66 85 C0 75 ?? 2B D1 D1 FA 75 ?? 33 C0 E9 ?? ?? ?? ?? 6A 40 8D 45 ?? 6A 00 50 E8 }
    condition:
        ($pdf and $agent) or (all of ($str*) and $a and $b)
}

rule Windows_Backdoor_Goldbackdoor_f11d57df {
    meta:
        id = "6AOC4umaAzTtYF5j6pAVXX"
        fingerprint = "v1_sha256_6401b215523289a3842dec6d3e016a2ca99512c5889e87cb5ff13023bb0b8e1e"
        version = "1.0"
        date = "2022-04-29"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Backdoor.Goldbackdoor"
        reference_sample = "45ece107409194f5f1ec2fbd902d041f055a914e664f8ed2aa1f90e223339039"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { C7 45 ?? 64 69 72 25 C7 45 ?? 5C 53 79 73 C7 45 ?? 74 65 6D 33 C7 45 ?? 32 5C 00 00 C7 45 ?? 2A 2E 65 78 C7 45 ?? 65 00 00 00 E8 ?? ?? ?? ?? FF D0 }
        $b = { B9 18 48 24 9D E8 ?? ?? ?? ?? FF D0 }
        $c = { B9 F8 92 FA 98 E8 ?? ?? ?? ?? FF D0 }
        $a1 = { 64 A1 30 00 00 00 53 55 56 }
        $b1 = { B9 76 DB 7A AA 6A 40 68 00 30 00 00 FF 75 ?? 50 E8 ?? ?? ?? ?? FF D0 }
        $c1 = { B9 91 51 13 EE 50 68 80 00 00 00 6A 04 50 50 ?? ?? ?? ?? ?? ?? ?? 6A 04 50 E8 ?? ?? ?? ?? FF D0 }
    condition:
        all of them
}

