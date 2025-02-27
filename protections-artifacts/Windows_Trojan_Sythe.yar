rule Windows_Trojan_Sythe_02b2811a {
    meta:
        id = "52e5N1vrtM1j3S1CwOKOu0"
        fingerprint = "v1_sha256_ba472b35f583dd4cf125df575129d07de289d6d7dc12ecdcc518ce1eb9f18def"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Sythe"
        reference_sample = "2d54a8ba40cc9a1c74db7a889bc75a38f16ae2d025268aa07851c1948daa1b4d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "loadmodule"
        $a2 = "--privileges"
        $a3 = "--shutdown"
        $a4 = "SetClientThreadID"
    condition:
        all of them
}

