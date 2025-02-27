rule Linux_Backdoor_Tinyshell_67ee6fae {
    meta:
        id = "1Tm80c1rko3BaFedoRBlDb"
        fingerprint = "v1_sha256_200d4267e21b8934deecc48273294f2e34464fcb412e39f3f5a006278631b9f1"
        version = "1.0"
        date = "2021-10-12"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Backdoor.Tinyshell"
        reference_sample = "9d2e25ec0208a55fba97ac70b23d3d3753e9b906b4546d1b14d8c92f8d8eb03d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]" fullword
        $a2 = "s:p:c::" fullword
        $b1 = "Usage: %s [ -s secret ] [ -p port ] [command]" fullword
        $b2 = "<hostname|cb> get <source-file> <dest-dir>" fullword
    condition:
        (all of ($a*)) or (all of ($b*))
}

