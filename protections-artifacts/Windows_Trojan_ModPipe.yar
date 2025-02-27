rule Windows_Trojan_ModPipe_12bc2604 {
    meta:
        id = "3Eye6obKksVcbEKYOSmPV3"
        fingerprint = "v1_sha256_0a26de1b2fb48d65cde61b60c0eba478da73a3eeaeb785d1b2d6095eccbe34e2"
        version = "1.0"
        date = "2023-07-27"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.ModPipe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0)" fullword
        $a2 = "/robots.txt" fullword
        $a3 = "www.yahoo.com/?"
        $a4 = "www.google.com/?"
    condition:
        all of them
}

