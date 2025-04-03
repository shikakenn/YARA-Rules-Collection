rule LUCKYMOUSE_Stolen_CERT
{
    meta:
        id = "2kcJTNMGMfwyVOet2iClub"
        fingerprint = "v1_sha256_a305e8839d01e4b84fc6d087d3aaa73803b20081977ad3626b5f4658abd9e93b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mikesxrs"
        description = "Certificate used to sign malware, could result in False positive due to it being legitimate"
        category = "INFO"
        reference = "https://securelist.com/luckymouse-ndisproxy-driver/87914/"

  strings:
    $STR1 = {78 62 07 2d dc 75 9e 5f 6a 61 4b e9 b9 3b d5 21}
    $STR2 = "ShenZhen LeagSoft Technology Co.,Ltd."
    
  condition: 
    all of them
}
