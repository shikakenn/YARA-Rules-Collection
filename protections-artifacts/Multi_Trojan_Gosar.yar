rule Multi_Trojan_Gosar_31dba745 {
    meta:
        id = "6xU0wsTWML5WUVQiL2LR7M"
        fingerprint = "v1_sha256_116fb9c44a992067d50cd95715ffa320c6141f133eb8c9dc91b2db8559a8ee2d"
        version = "1.0"
        date = "2024-11-05"
        modified = "2024-12-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Trojan.Gosar"
        reference_sample = "4caf4b280e61745ce53f96f48a74dea3b69df299c3b9de78ba4731b83c76c334"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "GetRecoverAccounts"
        $a2 = "GetIsFirstScreen"
        $a3 = "DoWebcamStop"
        $a4 = "DoAskElevate"
        $a5 = "vibrant/proto/pb"
        $a6 = "vibrant/network/sender"
        $a7 = "vibrant/pkg/helpers"
    condition:
        3 of them
}

