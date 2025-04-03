rule Windows_Trojan_Octopus_15813e26 {
    meta:
        id = "GMyWmQMnzB8MXJMFSQSZz"
        fingerprint = "v1_sha256_0d30b96ead4ccba75e08f6ba1db73cee61a29b5b0c7ee0fb523cbcd61dce9d87"
        version = "1.0"
        date = "2021-11-10"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Octopus, an Open source pre-operation C2 server based on Python and PowerShell"
        category = "INFO"
        threat_name = "Windows.Trojan.Octopus"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = "C:\\Users\\UNKNOWN\\source\\repos\\OctopusUnmanagedExe\\OctopusUnmanagedExe\\obj\\x64\\Release\\SystemConfiguration.pdb" ascii fullword
    condition:
        all of them
}

