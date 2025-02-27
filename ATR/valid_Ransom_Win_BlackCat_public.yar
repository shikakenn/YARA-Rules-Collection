
rule Ransom_Win_BlackCat
{
    meta:
        id = "PwTHAd6A5x0zJyYrJvy4v"
        fingerprint = "v1_sha256_8faad28ab26690221f6e2130c886446615dbd505f76490cfaf999d130d0de6e3"
        version = "1.0"
        date = "2022-01-06"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = " Trellix ATR"
        description = "Detecting variants of Windows BlackCat malware"
        category = "INFO"
        detection_name = "Ransom_Win_BlackCat"
        actor_group = "Unknown"

strings:

 $URL1 = "zujgzbu5y64xbmvc42addp4lxkoosb4tslf5mehnh7pvqjpwxn5gokyd.onion" ascii wide
 $URL2 = "mu75ltv3lxd24dbyu6gtvmnwybecigs5auki7fces437xvvflzva2nqd.onion" ascii wide

 $API = { 3a 7c d8 3f }

 condition:
  uint16(0) == 0x5a4d and
  filesize < 3500KB and
  1 of ($URL*) and
  $API
}
