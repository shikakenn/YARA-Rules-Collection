rule Windows_VulnDriver_RtCore_4eeb2ce5 {
    meta:
        id = "38Gdd3iy6jnmhAs6eCddPH"
        fingerprint = "v1_sha256_726a4f3cf5a5e5a9b15e30ccef680f9630f641caeed67fff42ecf49d61e997be"
        version = "1.0"
        date = "2022-04-04"
        modified = "2025-01-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\Device\\RTCore64" wide fullword
        $str2 = "Kaspersky Lab Anti-Rootkit Monitor Driver" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and uint32(uint32(0x3C) + 8) < 1713095596 and $str1 and not $str2
}

