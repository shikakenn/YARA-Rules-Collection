rule Windows_Trojan_Behinder_b9a49f4b {
    meta:
        id = "6kGHFQQpW3ke6BUQj3YxG1"
        fingerprint = "v1_sha256_2303ef82e4dc5e8be87ddc4563dcd06963d17e1fbf25cf246a6c81e4e74adbcb"
        version = "1.0"
        date = "2023-03-02"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Webshell found in REF2924, either Behinder or Godzilla based shell in C#"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/ref2924-howto-maintain-persistence-as-an-advanced-threat"
        threat_name = "Windows.Trojan.Behinder"
        reference_sample = "a50ca8df4181918fe0636272f31e19815f1b97cce6d871e15e03b0ee0e3da17b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $load = { 53 79 73 74 65 6D 2E 52 65 66 6C 65 63 74 69 6F 6E 2E 41 73 73 65 6D 62 6C 79 }
        $key = "e45e329feb5d925b" ascii wide
    condition:
        all of them
}

