rule Windows_Hacktool_AskCreds_34e3e3d4 {
    meta:
        id = "5QglSPYCVwTnHTguzfl1ZF"
        fingerprint = "v1_sha256_d911566ca546a8546928cd0ffa838fd344b35f75a4a7e80789d20e52c7cd38d0"
        version = "1.0"
        date = "2023-05-16"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.AskCreds"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Failed to create AskCreds thread."
        $a2 = "CredUIPromptForWindowsCredentialsW failed"
        $a3 = "[+] Password: %ls"
    condition:
        2 of them
}

