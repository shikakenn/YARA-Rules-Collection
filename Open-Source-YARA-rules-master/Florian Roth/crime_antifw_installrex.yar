
rule PUP_InstallRex_AntiFWb {
    meta:
        id = "30zdIj282BhRf4Lvt1WVTd"
        fingerprint = "v1_sha256_5248cc48554529b0cd2a44ab9e6ff6707e85b772fd9017fdc6bec407b380580a"
        version = "1.0"
        score = 65
        date = "2015-05-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Malware InstallRex / AntiFW"
        category = "INFO"
        hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"

    strings:
        $s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
        $s7 = "GetModuleFileName() failed => %u" fullword ascii
        $s8 = "TSULoader.exe" fullword wide
        $s15 = "\\StringFileInfo\\%04x%04x\\Arguments" fullword wide
        $s17 = "Tsu%08lX.dll" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
