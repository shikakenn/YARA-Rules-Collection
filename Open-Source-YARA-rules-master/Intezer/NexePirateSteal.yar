rule nexe_piratesteal {
    meta:
        id = "4GcisefoRPny67rBUeZccu"
        fingerprint = "v1_sha256_60686e33a35265289513797d4902dcd0baf2479a48b305001faf146f980d8c89"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer"
        description = "Hunting for Nexe compiled PirateStealer Dropper"
        category = "INFO"
        tlp = "white"

  strings:
        $nexe_str = "process.__nexe = {\"resources\""
        $steal_str0 = "file.includes(\"iscord\")"
        $steal_str1 = "\\app-*\\modules\\discord_desktop_core-*\\discord_desktop_core\\index.js"
        $steal_str2 = "pwnBetterDiscord"
  condition:
    (uint16(0) == 0x5A4D and $nexe_str and 2 of ($steal_str*))
}
