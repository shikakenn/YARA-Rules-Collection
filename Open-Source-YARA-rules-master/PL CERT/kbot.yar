rule kbot : banker
{
    meta:
        id = "7UyN4N15AinQpBgk2Sko2X"
        fingerprint = "v1_sha256_f85ebfb4ea74a76b55760ed2be9b88455372df1ee88dcbe38675535e32afffb0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mak"
        description = "NA"
        category = "INFO"
        reference = "https://www.cert.pl/en/news/single/newest-addition-a-happy-family-kbot/"
        module = "kbot"

    strings:
       $bot_cfg = "BASECONFIG......FJ"
       $injini  = "INJECTS.INI"
       $kbotini = "KBOT.INI"
       $bot0    = "BotConfig"
       $bot1    = "BotCommunity"
       $push_version = { 5? 68 [4] 68 [4] 5? E8 [4] 83 C4 10 85 C0 0F}
    condition: 
       all of them
}
