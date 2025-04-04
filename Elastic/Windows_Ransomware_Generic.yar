rule Windows_Ransomware_Generic_99f5a632 {
    meta:
        id = "6b1W7sWy744nWbSiz3k0Ym"
        fingerprint = "v1_sha256_2284cfc91d17816f1733e8fe319af52bc66af467364d27f84e213082c216ae8b"
        version = "1.0"
        date = "2022-02-24"
        modified = "2022-02-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Generic"
        reference_sample = "4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "stephanie.jones2024@protonmail.com"
        $a2 = "_/C_/projects/403forBiden/wHiteHousE.init" ascii fullword
        $a3 = "All your files, documents, photoes, videos, databases etc. have been successfully encrypted" ascii fullword
        $a4 = "<p>Do not try to decrypt then by yourself - it's impossible" ascii fullword
    condition:
        all of them
}

