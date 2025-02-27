rule Windows_Hacktool_Phant0m_2d6f9b57 {
    meta:
        id = "6NCz4Ivj1ehZZ6TExkR6tI"
        fingerprint = "v1_sha256_a66f8779f77b216f7831617a34c008e4202f36e74f2866c9792cee34b804408d"
        version = "1.0"
        date = "2024-02-28"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Phant0m"
        reference_sample = "30978aadd7d7bc86e735facb5046942792ad1beab6919754e6765e0ccbcf89d6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $api = "NtQueryInformationThread"
        $s1 = "Suspending EventLog thread %d with start address %p"
        $s2 = "Found the EventLog Module (wevtsvc.dll) at %p"
        $s3 = "Event Log service PID detected as %d."
        $s4 = "Thread %d is detected and successfully killed."
        $s5 = "Windows EventLog module %S at %p"
    condition:
        $api and 2 of ($s*)
}

