rule IPStorm
{
    meta:
        id = "495Wyt5K37qsuQrqMUfL7t"
        fingerprint = "v1_sha256_0cf02f887bca739c51cd06859269f543340b81cdcc73e0729d14dc16f868f62e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
        $package1 = "storm/backshell"
        $package2 = "storm/filetransfer"
        $package3 = "storm/scan_tools"
        $package4 = "storm/malware-guard"
        $package5 = "storm/avbypass"
        $package6 = "storm/powershell"
        $lib2b = "libp2p/go-libp2p"
        
    condition:
        4 of ($package*) and $lib2b
}
