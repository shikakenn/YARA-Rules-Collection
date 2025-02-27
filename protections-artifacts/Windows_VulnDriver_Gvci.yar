rule Windows_VulnDriver_Gvci_f5a35359 {
    meta:
        id = "5gILWWCXdRyHg43sUPzZod"
        fingerprint = "v1_sha256_beb0c324358a016e708dae30a222373113a7eab8e3d90dfa1bbde6c2f7874362"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Gvci"
        reference_sample = "42f0b036687cbd7717c9efed6991c00d4e3e7b032dc965a2556c02177dfdad0f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\GVCIDrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

