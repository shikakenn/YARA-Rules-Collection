rule Arkei
{
    meta:
        id = "PT3jYTzFal8Jt5UPbsO1B"
        fingerprint = "v1_sha256_296e420880d8d2f24424d0411e7ef4939e18147689557512f410da48498a44c9"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly, YungBinary"
        description = "Arkei Payload"
        category = "INFO"
        cape_type = "Arkei Payload"

    strings:
        $string1 = "Windows_Antimalware_Host_System_Worker"
        $string2 = "Arkei"
        $string3 = "Bitcoin\\wallet.dat"
        $string4 = "Ethereum\\keystore"

        $v1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii wide
        $v2 = "/c taskkill /im " fullword ascii
        $v3 = "card_number_encrypted FROM credit_cards" ascii
        $v4 = "\\wallet.dat" ascii
        $v5 = "Arkei/" wide
        $v6 = "files\\passwords." ascii wide
        $v7 = "files\\cc_" ascii wide
        $v8 = "files\\autofill_" ascii wide
        $v9 = "files\\cookies_" ascii wide
        
        $loaded_modules = {
            64 A1 30 00 00 00
            8B 40 0C
            8B 40 0C
            8B 00
            8B 00
            8B 40 18
            89 45 FC
            8B 45 FC
            8B E5
            5D
            C3
        }

        $language_check = {
            FF 15 ?? ?? ?? ??
            0F B7 C0
            89 45 ??
            81 7D ?? 3F 04 ?? ??
            7F
        }

        $ext1 = ".zoo" ascii
        $ext2 = ".arc" ascii

    condition:
        uint16(0) == 0x5A4D and (($loaded_modules and $language_check and $ext1 and $ext2) or (all of ($string*) or 7 of ($v*)))
}
