rule Windows_Trojan_DarkCloud_9905abce {
    meta:
        id = "4F5C9n1lVcThEgnMYli9Mg"
        fingerprint = "v1_sha256_27d3841d6acf87f5c9c03d643c7859d9eaf42e49ed0241b761f858c669c4e931"
        version = "1.0"
        date = "2023-05-03"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DarkCloud"
        reference_sample = "500cb8459c19acd5a1144c4b509c14dbddec74ad623896bfe946fde1cd99a571"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 8D 45 DC 57 57 6A 01 6A 11 50 6A 01 68 80 00 00 00 89 7D E8 89 }
        $a2 = { C8 33 FF 50 57 FF D6 8D 4D DC 51 57 FF D6 C3 8B 4D F0 8B 45 }
    condition:
        all of them
}

