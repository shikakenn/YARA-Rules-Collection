rule Linux_Hacktool_Aduh_6cae7c78 {
    meta:
        id = "6ukEc6RMZsODVhztdnuIWf"
        fingerprint = "v1_sha256_130df108de5b6cdfb9227f96301bdaa1e272d47b8cb9ad96c3aa574bf65870b2"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Aduh"
        reference_sample = "9c67207546ad274dc78a0819444d1c8805537f9ac36d3c53eba9278ed44b360c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E3 51 89 E2 51 89 E1 B0 0B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}

