/*
Author: Bit Byte Bitten
Date: 5/14/2015
*/

rule apt_backspace{
    meta:
        id = "3FOTnRPRRIGgHjb6NVXcmZ"
        fingerprint = "v1_sha256_6fa86ada5c965bd9c199c2a1cf9b691499a3d423da7db50c8987b6725c0c0f29"
        version = "1.0"
        date = "2015-05-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Bit Byte Bitten"
        description = "Detects APT backspace"
        category = "INFO"
        hash = "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99"

    strings:
        $s1 = "!! Use Splice Socket !!"
        $s2 = "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)"
        $s3 = "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"
    condition:
        uint16(0) == 0x5a4d and all of them
}
