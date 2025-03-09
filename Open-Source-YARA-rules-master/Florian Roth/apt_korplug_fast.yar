rule Korplug_FAST {
    meta:
        id = "5Hqc8JmC0weoJQxS8HtdzE"
        fingerprint = "v1_sha256_19923eb565dff74f16f53ed98269d0d40dc5d2556ded7147e4b2a0ad3bc0d58c"
        version = "1.0"
        date = "2015-08-20"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Rule to detect Korplug/PlugX FAST variant"
        category = "INFO"
        hash = "c437465db42268332543fbf6fd6a560ca010f19e0fd56562fb83fb704824b371"

    strings:
        $x1 = "%s\\rundll32.exe \"%s\", ShadowPlay" fullword ascii

        $a1 = "ShadowPlay" fullword ascii

        $s1 = "%s\\rundll32.exe \"%s\"," fullword ascii
        $s2 = "nvdisps.dll" fullword ascii
        $s3 = "%snvdisps.dll" fullword ascii
        $s4 = "\\winhlp32.exe" fullword ascii
        $s5 = "nvdisps_user.dat" fullword ascii
        $s6 = "%snvdisps_user.dat" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 
        (
            $x1 or
            ($a1 and 1 of ($s*)) or 
            4 of ($s*)
        )
}
