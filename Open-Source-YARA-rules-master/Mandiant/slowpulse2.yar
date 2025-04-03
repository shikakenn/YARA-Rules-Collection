rule FE_APT_Backdoor_Linux32_SLOWPULSE_2
{ 
    meta:
        id = "6Bz0yk6DKVbULHeVpm7UwH"
        fingerprint = "v1_sha256_5554c551564498fb19441a35a810fcba11a3e635b933371871594fc505ef63a9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Strozfriedberg"
        description = "NA"
        category = "INFO"
        date_created = "2021-04-16"
        sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"

    strings: 
        $sig = /[\x20-\x7F]{16}([\x20-\x7F\x00]+)\x00.{1,32}\xE9.{3}\xFF\x00+[\x20-\x7F][\x20-\x7F\x00]{16}/ 

        // TOI_MAGIC_STRING 
        $exc1 = {ED C3 02 E9 98 56 E5 0C}
    condition:
        uint32(0) == 0x464C457F and (1 of ($sig*)) and (not (1 of ($exc*)))
}
