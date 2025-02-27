rule Linux_Cryptominer_Casdet_5d0d33be {
    meta:
        id = "XCuWOZEWmotAdUGTZWng0"
        fingerprint = "v1_sha256_e3264f614e257d853070907866b838d1cb53c1f60f7a0123ec503f1d540a15d7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Casdet"
        reference_sample = "4b09115c876a8b610e1941c768100e03c963c76b250fdd5b12a74253ef9e5fb6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C3 EB 05 48 89 C3 EB CF 48 8B BC 24 A0 00 00 00 48 85 FF 74 D7 48 }
    condition:
        all of them
}

