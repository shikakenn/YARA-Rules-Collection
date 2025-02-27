rule Windows_Trojan_WhisperGate_9192618b {
    meta:
        id = "39N62F0f8Ij2XJxyhnvjTh"
        fingerprint = "v1_sha256_28bb08d61d99d2bfc49ba18cdbabc34c31a715ae6439ab25bbce8cc6958ed381"
        version = "1.0"
        date = "2022-01-17"
        modified = "2022-01-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/operation-bleeding-bear"
        threat_name = "Windows.Trojan.WhisperGate"
        reference_sample = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "https://cdn.discordapp.com/attachments/" wide
        $a2 = "DxownxloxadDxatxxax" wide fullword
        $a3 = "powershell" wide fullword
        $a4 = "-enc UwB0AGEAcgB0AC" wide fullword
        $a5 = "Ylfwdwgmpilzyaph" wide fullword
    condition:
        all of them
}

