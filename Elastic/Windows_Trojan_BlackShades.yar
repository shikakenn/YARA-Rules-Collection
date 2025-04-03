rule Windows_Trojan_BlackShades_9d095c44 {
    meta:
        id = "26vBp3tqAaCIYxKGnE2RLK"
        fingerprint = "v1_sha256_2a2e6325d3de9289cc8bc26e1fe89a8fa81d9aae50b92ba2cf21c4cc6556ac9e"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BlackShades"
        reference_sample = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
        $a2 = "@*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
        $a3 = "D:\\Blackshades Project\\bs_net\\loginserver\\msvbvm60.dll\\3" ascii fullword
        $b1 = "modSniff" ascii fullword
        $b2 = "UDPFlood" ascii fullword
        $b3 = "\\nir_cmd.bss speak text " wide fullword
        $b4 = "\\pws_chro.bss" wide fullword
        $b5 = "tmrLiveLogger" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_BlackShades_be382dac {
    meta:
        id = "3xB9oyy5wVo1N2w0HCJTBY"
        fingerprint = "v1_sha256_a13e37e7930d2d1ed1aa4fdeb282f11bfeb7fe008625589e2bfeab0beea43580"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BlackShades"
        reference_sample = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 10 54 }
    condition:
        all of them
}

