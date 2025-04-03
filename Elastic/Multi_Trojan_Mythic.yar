rule Multi_Trojan_Mythic_4beb7e17 {
    meta:
        id = "1dGE3Q1mE05ZbKG5mILwJ6"
        fingerprint = "v1_sha256_7b3b7bae1763f3c73df206f97065920fa55b973d22c967acb3d26ac8e89e60c7"
        version = "1.0"
        date = "2023-08-01"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Trojan.Mythic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "task_id"
        $a2 = "post_response"
        $a3 = "c2_profile"
        $a4 = "get_tasking"
        $a5 = "tasking_size"
        $a6 = "get_delegate_tasks"
        $a7 = "total_chunks"
        $a8 = "is_screenshot"
        $a9 = "file_browser"
        $a10 = "is_file"
        $a11 = "access_time"
    condition:
        7 of them
}

rule Multi_Trojan_Mythic_e0ea7ef9 {
    meta:
        id = "5RqTpddvLOaP2eALDduTdd"
        fingerprint = "v1_sha256_237307d85fe7886eb2cf351a9f7872e3e5551f05535f0b6a966a960d204aee90"
        version = "1.0"
        date = "2024-05-23"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "e091d63c8e8b0a32a3d25cffdf02419fdbec714f31e4061bafd80b1971831c5f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $profile1 = "src/profiles/mod.rs"
        $profile2 = "src/profiles/http.rs"
        $rs_ssh1 = "src/ssh/spawn.rs"
        $rs_ssh2 = "src/ssh/agent.rs"
        $rs_ssh3 = "src/ssh/cat.rs"
        $rs_ssh4 = "src/ssh/upload.rs"
        $rs_ssh5 = "src/ssh/exec.rs"
        $rs_ssh6 = "src/ssh/download.rs"
        $rs_ssh7 = "src/ssh/rm.rs"
        $rs_ssh8 = "src/ssh/ls.rs"
        $rs_misc1 = "src/utils/linux.rs"
        $rs_misc2 = "src/portscan.rs"
        $rs_misc3 = "src/payloadvars.rs"
        $rs_misc4 = "src/getprivs.rs"
    condition:
        all of ($profile*) and 8 of ($rs*)
}

rule Multi_Trojan_Mythic_528324b4 {
    meta:
        id = "5SBAo1oBIUeB0HwrFN9asn"
        fingerprint = "v1_sha256_8c85d086b30030a24fba9f519aed3fdf3c821932d71ceaecfe354fe07cd1d631"
        version = "1.0"
        date = "2024-05-23"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "2cd883eab722a5eacbca7fa82e0eebb5f6c30cffa955abcb1ab8cf169af97202"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $import1 = "Autofac"
        $import2 = "Obfuscar"
        $import3 = "Agent.Profiles.Http"
        $import4 = "Agent.Managers.Linux"
        $import5 = "Agent.Managers.Reflection"
        $athena1 = "Athena.Commands.dll"
        $athena2 = "Athena.Handler.Linux.dll"
        $athena3 = "Athena.dll"
        $athena4 = "Athena.Profiles.HTTP.dll"
    condition:
        (2 of ($import*)) or (2 of ($athena*))
}

