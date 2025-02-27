rule Linux_Hacktool_LigoloNG_027c0134 {
    meta:
        id = "4B9WpZeDf7q3RV33ISrsY6"
        fingerprint = "v1_sha256_a6f3c1f4c044765d841992758f451666e8bf5225e1a9f02925619c99fe8e03cb"
        version = "1.0"
        date = "2024-09-20"
        modified = "2024-11-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.LigoloNG"
        reference_sample = "eda6037bda3ccf6bbbaf105be0826669d5c4ac205273fefe103d8c648271de54"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = "https://github.com/nicocha30/ligolo-ng"
        $b = "@Nicocha30!"
        $c = "Ligolo-ng %s / %s / %s"
    condition:
        all of them
}

