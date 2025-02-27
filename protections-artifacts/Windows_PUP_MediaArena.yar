rule Windows_PUP_MediaArena_a9e3b4a1 {
    meta:
        id = "4WM6kJ0onRQbuu5BjgKR6D"
        fingerprint = "v1_sha256_8e52b29f2848498aae2fd7ad35494362d6c07f0e752b628840a256923aca32c7"
        version = "1.0"
        date = "2023-06-02"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.PUP.MediaArena"
        reference_sample = "c071e0b67e4c105c87b876183900f97a4e8bc1a7c18e61c028dee59ce690b1ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Going to change default browser to be MS Edge ..." wide
        $a2 = "https://www.searcharchiver.com/eula" wide
        $a3 = "Current default browser is unchanged!" wide
        $a4 = "You can terminate your use of the Search Technology and Search Technology services"
        $a5 = "The software may also offer to change your current web navigation access points"
        $a6 = "{{BRAND_NAME}} may have various version compatible with different platform,"
        $a7 = "{{BRAND_NAME}} is a powerful search tool" wide
    condition:
        2 of them
}

