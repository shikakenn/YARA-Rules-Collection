rule Multi_Trojan_Merlin_32643f4c {
    meta:
        id = "2RoZq3sC90CdhHmBF6xfby"
        fingerprint = "v1_sha256_7de2deec0e2c7fd3ce2b42762f88bfe87cb4ffb02b697953aa1716425d6f1612"
        version = "1.0"
        date = "2024-03-01"
        modified = "2024-05-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Trojan.Merlin"
        reference_sample = "84b988c4656677bc021e23df2a81258212d9ceba13be204867ac1d9d706404e2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "json:\"killdate,omitempty\""
        $a2 = "json:\"maxretry,omitempty\""
        $a3 = "json:\"waittime,omitempty\""
        $a4 = "json:\"payload,omitempty\""
        $a5 = "json:\"skew,omitempty\""
        $a6 = "json:\"command\""
        $a7 = "json:\"pid,omitempty\""
        $b1 = "/merlin-agent/commands"
        $b2 = "/merlin/pkg/jobs"
        $b3 = "github.com/Ne0nd0g/merlin"
    condition:
        all of ($a*) or all of ($b*)
}

