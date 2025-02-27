rule Windows_Hacktool_Certify_ffe1cca2 {
    meta:
        id = "6bE0XNlHHL4rvFPSf0YhRN"
        fingerprint = "v1_sha256_e1d37ad683bfbe34433dc5e13ae2cf7c873fed640e1c58a3b0274b4b34900e53"
        version = "1.0"
        date = "2024-03-27"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Certify"
        reference_sample = "3c7f759a6c38d0c0780fba2d43be6dcf9e4869d54b66f16c0703ec8e58124953"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "<DisplayNtAuthCertificates>b_"
        $a2 = "<PrintAllowPermissions>b_"
        $a3 = "<ShowVulnerableTemplates>b_"
        $a4 = "<ParseCertificateApplicationPolicies>b_"
        $a5 = "<PrintCertTemplate>b_"
        $b1 = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide nocase
        $b2 = "64524CA5-E4D0-41B3-ACC3-3BDBEFD40C97" ascii wide nocase
        $b3 = "Certify.exe find /vulnerable" wide
        $b4 = "Certify.exe request /ca" wide
    condition:
        all of ($a*) or any of ($b*)
}

