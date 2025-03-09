/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-07-20
    Identifier: MiniDionis
*/

/* Rule Set ----------------------------------------------------------------- */

rule MiniDionis_readerView {
    meta:
        id = "5mDRSPRA6YTPtd56z07h1j"
        fingerprint = "v1_sha256_45ae1be675f2b7b3d89aea2bde66f9f96b55b6fbf81e3783c209c7d6d4355026"
        version = "1.0"
        date = "2015-07-20"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "MiniDionis Malware - file readerView.exe / adobe.exe"
        category = "INFO"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        hash1 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
        hash2 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
        hash3 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
        hash4 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
        hash5 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
        hash6 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"

    strings:
        $s1 = "%ws_out%ws" fullword wide /* score: '8.00' */
        $s2 = "dnlibsh" fullword ascii /* score: '7.00' */

        $op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b } /* Opcode */
        $op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f } /* Opcode */
        $op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 } /* Opcode */
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) and 1 of ($op*)
}

/* Related - SFX files or packed files with typical malware content -------- */

rule Malicious_SFX1 {
    meta:
        id = "6369WU4jlXhl0E991vR9H4"
        fingerprint = "v1_sha256_fd7b4c504a52e68fe87eeb9f7066c61ddc47257ac9324a60d219c022d3affbbf"
        version = "1.0"
        date = "2015-07-20"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "SFX with voicemail content"
        category = "INFO"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        hash = "c0675b84f5960e95962d299d4c41511bbf6f8f5f5585bdacd1ae567e904cb92f"

    strings:
        $s0 = "voicemail" ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
        $s1 = ".exe" ascii
    condition:
        uint16(0) == 0x4b50 and filesize < 1000KB and $s0 in (3..80) and $s1 in (3..80) 
}

rule Malicious_SFX2 {
    meta:
        id = "5OnrmCxQ7Fj620wbim2QpO"
        fingerprint = "v1_sha256_a2ed7660604ff3c9f2d0dbb454f5d168cd61d1d5e647b5c74fe24f25ebb3dbfd"
        version = "1.0"
        date = "2015-07-20"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "SFX with adobe.exe content"
        category = "INFO"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        hash = "502e42dc99873c52c3ca11dd3df25aad40d2b083069e8c22dd45da887f81d14d"

    strings:
        $s1 = "adobe.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
        $s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00' */
        $s3 = "GETPASSWORD1" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule MiniDionis_VBS_Dropped {
    meta:
        id = "TtlDejC6S8aUg1C9M6Osc"
        fingerprint = "v1_sha256_a24fe4cdff6dd7951af10710eb63ab1fd90ab0e43bbce4388d6687abac206da5"
        version = "1.0"
        date = "2015-07-21"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Dropped File - 1.vbs"
        category = "INFO"
        reference = "https://malwr.com/analysis/ZDc4ZmIyZDI4MTVjNGY5NWI0YzE3YjIzNGFjZTcyYTY/"
        hash = "97dd1ee3aca815eb655a5de9e9e8945e7ba57f458019be6e1b9acb5731fa6646"

    strings:
        $s1 = "Wscript.Sleep 5000" ascii
        $s2 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii
        $s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii
        $s4 = "If(FSO.FileExists(\"" ascii
        $s5 = "then FSO.DeleteFile(\".\\" ascii
    condition:
        filesize < 1KB and all of them and $s1 in (0..40)
}
