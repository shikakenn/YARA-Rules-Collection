rule Linux_Backdoor_Bash_e427876d {
    meta:
        id = "2ipl1buJlGalLYXObBAANS"
        fingerprint = "v1_sha256_fdd066b746416730419787d21eb53fa2ba997679a237d9db3a2e1365d43df892"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Backdoor.Bash"
        reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 67 65 44 6F 6B 4B 47 6C 6B 49 43 31 31 4B 54 6F 67 4C 32 56 }
    condition:
        all of them
}

