rule Intezer_Vaccine_Gh0stRat
{
    meta:
        id = "A69XmPQt6npfnVd4AJZci"
        fingerprint = "v1_sha256_56da61307e19a82058b4ac106d0ab263903835075583529e02bc7a8ac58cc734"
        version = "1.0"
        date = "2019-10-30"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "Automatic YARA vaccination rule created based on the file's genes"
        category = "INFO"
        reference = "https://analyze.intezer.com"
        copyright = "Intezer Labs"
        sha256 = "5eeeccb6a48fcaad0fe1c34ff52e241af309bc820b4c7a445c3aca8026da77d5"

    strings:
        $4233486_212 = { 8D ?? ?? 5? 8B ?? ?? ?? ?? ?? 81 C? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 6A ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? C1 ?? ?? 8B ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? ?? 5? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? C1 ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 89 ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? C1 ?? ?? 8B ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? ?? 5? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? C1 ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 89 ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 0F 85 }
        $4201392_196 = { 5? 8B ?? 6A ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? 5? 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 8D ?? ?? 5? E8 ?? ?? ?? ?? 5? 8B ?? ?? 81 C? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 8D ?? ?? E8 ?? ?? ?? ?? 5? 8B ?? 89 ?? ?? 8D ?? ?? 5? E8 ?? ?? ?? ?? 8B ?? ?? 81 C? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D ?? ?? 5? E8 ?? ?? ?? ?? 89 ?? ?? 8B ?? ?? 89 ?? ?? C6 ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 5? 8D ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? C6 ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? ?? 0F 84 }
        $4201787_132 = { 5? 8B ?? 6A ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? 5? 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? 6A ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D ?? ?? 5? E8 ?? ?? ?? ?? 89 ?? ?? 8B ?? ?? 89 ?? ?? C6 ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 5? 8D ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? C6 ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? ?? 0F 84 }
        $4202398_128 = { 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 0F BF ?? ?? ?? ?? ?? 83 ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 0F BF ?? ?? ?? ?? ?? 5? 8B ?? ?? ?? ?? ?? 5? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BF ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? C6 ?? ?? ?? 8B ?? ?? ?? ?? ?? 5? 8B ?? ?? ?? ?? ?? 81 C? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 8D ?? ?? ?? ?? ?? E8 }
        $4202228_113 = { 8D ?? ?? ?? ?? ?? 5? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? C6 ?? ?? ?? 8B ?? ?? ?? ?? ?? 5? 8D ?? ?? E8 ?? ?? ?? ?? C6 ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 ?? ?? ?? 6A ?? 6A ?? 8D ?? ?? E8 ?? ?? ?? ?? 5? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
        $4202127_97 = { 5? 8B ?? 6A ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? 5? 64 ?? ?? ?? ?? ?? ?? 81 E? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 0F 85 }
        $4225201_72 = { 5? 8B ?? 6A ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? 5? 64 ?? ?? ?? ?? ?? ?? 5? 83 ?? ?? 5? 5? 5? 89 ?? ?? C7 ?? ?? ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? 89 ?? ?? 8B ?? ?? 8B ?? 05 ?? ?? ?? ?? 89 ?? ?? 8B ?? ?? 83 ?? ?? ?? 0F 86 }
        $4233420_62 = { 5? 8B ?? 6A ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? 5? 64 ?? ?? ?? ?? ?? ?? 81 E? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 81 C? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 83 ?? ?? ?? 0F 84 }
        $4206491_45 = { 8B ?? ?? ?? ?? ?? 5? 6A ?? 6A ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 0F 85 }
        $4233167_43 = { 6A ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 0F 85 }
        $4224206_35 = { 8B ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 8B ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 8B ?? ?? 8B ?? 83 ?? ?? ?? 0F 84 }
        $4226055_33 = { 5? 8B ?? 83 ?? ?? 8B ?? ?? 25 ?? ?? ?? ?? 99 B9 ?? ?? ?? ?? F7 ?? 88 ?? ?? C7 ?? ?? ?? ?? ?? ?? EB }
        $4233881_32 = { 5? 8B ?? 83 ?? ?? 89 ?? ?? 8B ?? ?? 81 C? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 83 ?? ?? ?? 0F 84 }
        $4201240_29 = { 8B ?? ?? 99 B9 ?? ?? ?? ?? F7 ?? 8B ?? 99 B9 ?? ?? ?? ?? F7 ?? 89 ?? ?? 83 ?? ?? ?? 7F }
        $4201144_22 = { 8B ?? ?? 99 B9 ?? ?? ?? ?? F7 ?? 89 ?? ?? 81 7? ?? ?? ?? ?? ?? 7F }
        $4214828_21 = { 5? 8B ?? 83 ?? ?? 89 ?? ?? 8B ?? ?? 89 ?? ?? 83 ?? ?? ?? 0F 84 }
        $4215402_17 = { B9 ?? ?? ?? ?? 2B ?? ?? 89 ?? ?? 83 ?? ?? ?? 0F 84 }
        $4224500_16 = { 8B ?? ?? 8B ?? 33 ?? 66 ?? ?? ?? 39 ?? ?? 0F 8D }
        $4225299_16 = { 6A ?? 8B ?? ?? 5? FF 1? ?? ?? ?? ?? 85 ?? 0F 85 }
        $4206280_15 = { 8B ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 0F 85 }
        $4234593_14 = { 8B ?? ?? 8B ?? ?? 3B ?? ?? ?? ?? ?? 0F 8D }
        $4207137_13 = { 5? 8B ?? 5? 89 ?? ?? 83 ?? ?? ?? 0F 85 }
        $4205965_12 = { 8B ?? ?? 83 ?? ?? ?? ?? ?? ?? 0F 85 }

    condition:
        17 of them
}
