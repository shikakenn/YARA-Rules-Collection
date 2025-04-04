rule Windows_Trojan_Buerloader_c8a60f46 {
    meta:
        id = "nGjowQqafAjcs9puTSPy"
        fingerprint = "v1_sha256_d11b117efc10547e77ce8979f8a1d42f34937101e58a0e36228baa37cd30d2aa"
        version = "1.0"
        date = "2021-08-16"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Buerloader"
        reference_sample = "3abed86f46c8be754239f8c878f035efaae91c33b8eb8818c5bbed98c4d9a3ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "User-Agent: Host:  HTTP/1.1" ascii fullword
        $a2 = "ServerHelloPayloadrandom" ascii fullword
        $a3 = "Bad JSON in payload" ascii fullword
        $a4 = { 7B 22 68 65 6C 6C 6F 22 3A 20 22 77 6F 72 6C 64 22 7D 48 54 54 50 2F 31 2E 31 20 33 30 31 20 46 6F 75 6E 64 }
        $a5 = "PayloadU24UnknownExtensiontyp" ascii fullword
        $a6 = " NTDLL.DLL" wide fullword
    condition:
        all of them
}

