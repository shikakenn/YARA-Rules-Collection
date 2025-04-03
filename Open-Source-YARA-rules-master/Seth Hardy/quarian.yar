private rule QuarianCode : Quarian Family 
{
    meta:
        id = "5t8m7ti3vCdxUQpxi3hnWu"
        fingerprint = "v1_sha256_d4ccfebce3d5f08d73a8bcdead2faa751f1b82afa20c8e46082a3bcc273b3139"
        version = "1.0"
        modified = "2014-07-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Quarian code features"
        category = "INFO"

    strings:
        // decrypt in intelnat.sys
        $ = { C1 E? 04 8B ?? F? C1 E? 05 33 C? }
        // decrypt in mswsocket.dll
        $ = { C1 EF 05 C1 E3 04 33 FB }
        $ = { 33 D8 81 EE 47 86 C8 61 }
        // loop in msupdate.dll
        $ = { FF 45 E8 81 45 EC CC 00 00 00 E9 95 FE FF FF }
    
    condition:
        any of them
}

private rule QuarianStrings : Quarian Family
{
    meta:
        id = "7ifSjbmQVLo2vJvDvFsJYo"
        fingerprint = "v1_sha256_748b7afff72546ba842c138693e969e3b620d07c559e2bc897cab71618daff1d"
        version = "1.0"
        modified = "2014-07-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Quarian Identifying Strings"
        category = "INFO"

    strings:
        $ = "s061779s061750"
        $ = "[OnUpLoadFile]"
        $ = "[OnDownLoadFile]"
        $ = "[FileTransfer]"
        $ = "---- Not connect the Manager, so start UnInstall ----"
        $ = "------- Enter CompressDownLoadDir ---------"
        $ = "------- Enter DownLoadDirectory ---------"
        $ = "[HandleAdditionalData]"
        $ = "[mswsocket.dll]"
        $ = "msupdate.dll........Enter ThreadCmd!"
        $ = "ok1-1"
        $ = "msupdate_tmp.dll"
        $ = "replace Rpcss.dll successfully!"
        $ = "f:\\loadhiddendriver-mdl\\objfre_win7_x86\\i386\\intelnat.pdb"
        $ = "\\drivercashe\\" wide ascii
        $ = "\\microsoft\\windwos\\" wide ascii
        $ = "\\DosDevices\\LOADHIDDENDRIVER" wide ascii
        $ = "\\Device\\LOADHIDDENDRIVER" wide ascii
        $ = "Global\\state_maping" wide ascii
        $ = "E:\\Code\\2.0\\2.0_multi-port\\2.0\\ServerInstall_New-2010-0913_sp3\\msupdataDll\\Release\\msupdate_tmp.pdb"
        $ = "Global\\unInstall_event_1554_Ower" wide ascii
        
    condition:
       any of them
}

rule Quarian : Family
{
    meta:
        id = "59S1slulMU0vD5iMYgqmu1"
        fingerprint = "v1_sha256_00aff01d3b855631d37bd9ba89d8dd0c64f3161ca7d753d00d8cdcaf1e808704"
        version = "1.0"
        modified = "2014-07-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Quarian"
        category = "INFO"

    condition:
        QuarianCode or QuarianStrings
}
