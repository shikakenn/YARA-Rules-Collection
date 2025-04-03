// yara rules that can cross boundaries between the various sets/types... more general detection signatures
import "pe"

rule wiper_unique_strings
{
    meta:
        id = "hVLyfZoU80xogkVt2zIKO"
        fingerprint = "v1_sha256_caf2a2036b071a358df78e09dff62999e9a4beed4830539afa94108d20ed6e74"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        company = "novetta"

     strings:
         $a = "C!@I#%VJSIEOTQWPVz034vuA"
        $b = "BAISEO%$2fas9vQsfvx%$"
        $c = "1.2.7.f-hanba-win64-v1"
        $d = "md %s&copy %s\\*.* %s"
        $e = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
        $f = "Ge.tVol. .umeIn..for  mati.onW"
    
    condition:
        $a or $b or $c or $d or $e or $f
}


rule wiper_encoded_strings
{
    meta:
        id = "2ERfbFiSqgn34OpNxlrIhu"
        fingerprint = "v1_sha256_4c1a223643483756ebc81799f0d23001019bd34fffb55e454f4245cf77033876"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        company = "novetta"

     strings:
         $scr = {89 D4 C4 D5 00 00 00}
         $explorer = {E2 DF D7 CB C8 D5 C2 D5 89 C2 DF C2 00 00 00 }
         $kernel32 = {CC C2 D5 C9 C2 CB 94 95  89 C3 CB CB 00 00 }

    condition:
        $scr or $explorer or $kernel32 
}


rule createP2P
{
    meta:
        id = "5m4XDOrot4Ty898x1lazx9"
        fingerprint = "v1_sha256_1e9c0cb30afa14a605a58ae2738538b8aec1b3806b094a2c1c57df503ea7849a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $ = "CreatP2P Thread" wide

    condition:
        any of them
}

rule firewallOpener
{
    meta:
        id = "OFlQppWSJqTI5qoAPcglc"
        fingerprint = "v1_sha256_042b48132b508dcd8b5c0ef2400624ed17b7f9bffc584410749aeede4f618c16"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
     $ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
     
    condition:
        any of them
        
}
