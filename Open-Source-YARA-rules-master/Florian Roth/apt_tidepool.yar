/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-05-24
    Identifier: TidePool (Ke3chang)
*/

rule TidePool_Malware {
    meta:
        id = "1unlJZsHjq3PGlJoES4int"
        fingerprint = "v1_sha256_759920ed7c9320e8412ed0644b28922a545b04f7549f0da6d6c67d6af8a7af3e"
        version = "1.0"
        date = "2016-05-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"
        category = "INFO"
        reference = "http://goo.gl/m2CXWR"
        hash1 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
        hash2 = "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed"
        hash3 = "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18"
        hash4 = "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f"
        hash5 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"

    strings:
        $x1 = "Content-Disposition: form-data; name=\"m1.jpg\"" fullword ascii
        $x2 = "C:\\PROGRA~2\\IEHelper\\mshtml.dll" fullword wide
        $x3 = "C:\\DOCUME~1\\ALLUSE~1\\IEHelper\\mshtml.dll" fullword wide
        $x4 = "IEComDll.dat" fullword ascii

        $s1 = "Content-Type: multipart/form-data; boundary=----=_Part_%x" fullword wide
        $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword wide
        $s3 = "network.proxy.socks_port\", " fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) ) ) or ( 4 of them )
}
