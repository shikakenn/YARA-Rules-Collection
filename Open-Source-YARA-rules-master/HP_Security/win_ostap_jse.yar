rule win_ostap_jse {
    meta:
        id = "5LBlU0nqVlqvhFiTtqXHA5"
        fingerprint = "v1_sha256_706b1045f42bfa29ad69ec83755ec526aba509205b1fd700e6c1b843174958ae"
        version = "1.0"
        date = "2019-08-29"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Alex Holland @cryptogramfan (Bromium Labs)"
        description = "NA"
        category = "INFO"
        reference = "https://threatresearch.ext.hp.com/deobfuscating-ostap-trickbots-javascript-downloader/"
        sample_1 = "F3E03E40F00EA10592F20D83E3C5E922A1CE6EA36FC326511C38F45B9C9B6586"
        sample_2 = "38E2B6F06C2375A955BEA0337F087625B4E6E49F6E4246B50ECB567158B3717B"

    strings:
        $comment = { 2A 2A 2F 3B } // Matches on **/;
        $array_0 = /\w{5,8}\[\d+\]=\d{1,3};/
        $array_1 = /\w{5,8}\[\d+\]=\d{1,3};/
                
    condition:
        ((($comment at 0) and (#array_0 > 100) and (#array_1 > 100)) or
        ((#array_0 > 100) and (#array_1 > 100))) and
        (filesize > 500KB and filesize < 1500KB)
}
