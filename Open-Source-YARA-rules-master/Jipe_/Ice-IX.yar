rule ice_ix_12xy : banker
{
    meta:
        id = "6iKpaNUe0FukIYJVNJW2xu"
        fingerprint = "v1_sha256_93b8a70c2034ad5178f3da91e3fdcff13e77f13c5547fe54fe8db86603ab93a0"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "ICE-IX 1.2.x.y trojan banker"
        category = "INFO"
        filetype = "memory"

    strings:
        $regexp1= /bn1=.{32}&sk1=[0-9a-zA-Z]{32}/
        $a = "bn1="
        $b = "&sk1="
        $c = "mario"								//HardDrive GUID artifact
        $d = "FIXME"
        $e = "RFB 003.003"							//VNC artifact
        $ggurl = "http://www.google.com/webhp"

    condition:
        $regexp1 or ($a and $b) or all of ($c,$d,$e,$ggurl) 
}
