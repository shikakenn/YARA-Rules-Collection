rule Windows_Trojan_MyloBot_a895174a {
    meta:
        id = "1JgIsbRooquovektHws5M2"
        fingerprint = "v1_sha256_16f2d8eeb6c85944030a33bd250e4e8b98985a6c877a0ec3ad5a6037e7c00159"
        version = "1.0"
        date = "2024-05-15"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.MyloBot"
        reference_sample = "33831d9ad64d0f52f507f08ef81607aafa6ced58a189969af6cf57c659c982d2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%s\\%s.lnk" wide fullword
        $a2 = "%s\\%s.exe" wide fullword
        $a3 = "%s\\%s\\%s.exe" wide fullword
        $a4 = "HTTP/1.0 502" ascii fullword
        $a5 = "/c \"%ws '%ws%s'\"" ascii fullword
        $a6 = ">> %ws %ws %ws" ascii fullword
        $a7 = "%s\\DefaultIcon" ascii fullword
    condition:
        all of them
}

