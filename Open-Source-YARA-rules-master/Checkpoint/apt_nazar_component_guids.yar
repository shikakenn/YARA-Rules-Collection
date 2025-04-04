rule apt_nazar_component_guids
{
    meta:
        id = "uju3Rd4ZdJ7cLlxKOQpBJ"
        fingerprint = "v1_sha256_9fb69a0ea7272f1b1cbb290ae81e08f7e2b2f6c5409bbca12d9b0b781cb4c267"
        version = "1.0"
        date = "2020-04-27"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Itay Cohen"
        description = "Detect Nazar Components by COM Objects' GUID"
        category = "INFO"
        reference = "<https://www.epicturla.com/blog/the-lost-nazar>"
        hash = "1110c3e34b6bbaadc5082fabbdd69f492f3b1480724b879a3df0035ff487fd6f"
        hash = "1afe00b54856628d760b711534779da16c69f542ddc1bb835816aa92ed556390"
        hash = "2caedd0b2ea45761332a530327f74ca5b1a71301270d1e2e670b7fa34b6f338e"
        hash = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
        hash = "460eba344823766fe7c8f13b647b4d5d979ce4041dd5cb4a6d538783d96b2ef8"
        hash = "4d0ab3951df93589a874192569cac88f7107f595600e274f52e2b75f68593bca"
        hash = "75e4d73252c753cd8e177820eb261cd72fecd7360cc8ec3feeab7bd129c01ff6"
        hash = "8fb9a22b20a338d90c7ceb9424d079a61ca7ccb7f78ffb7d74d2f403ae9fbeec"
        hash = "967ac245e8429e3b725463a5c4c42fbdf98385ee6f25254e48b9492df21f2d0b"
        hash = "be624acab7dfe6282bbb32b41b10a98b6189ab3a8d9520e7447214a7e5c27728"
        hash = "d34a996826ea5a028f5b4713c797247913f036ca0063cc4c18d8b04736fa0b65"
        hash = "d9801b4da1dbc5264e83029abb93e800d3c9971c650ecc2df5f85bcc10c7bd61"
        hash = "eb705459c2b37fba5747c73ce4870497aa1d4de22c97aaea4af38cdc899b51d3"
        reference2 = "https://research.checkpoint.com/2020/nazar-spirits-of-the-past/"

    strings:
        $guid1_godown = { 98 B3 E5 F6 DF E3 6B 49 A2 AD C2 0F EA 30 DB FE } // Godown.dll IID
        $guid2_godown = { 31 4B CB DB B8 21 0F 4A BC 69 0C 3C E3 B6 6D 00 } // Godown.dll CLSID
        $guid3_godown = { AF 94 4E B6 6B D5 B4 48 B1 78 AF 07 23 E7 2A B5 } // probably Godown
        $guid4_filesystem = { 79 27 AB 37 34 F2 9D 4D B3 FB 59 A3 FA CB 8D 60 } // Filesystem.dll CLSID
        $guid6_filesystem = { 2D A1 2B 77 62 8A D3 4D B3 E8 92 DA 70 2E 6F 3D } // Filesystem.dll TypeLib IID
        $guid5_filesystem = { AB D3 13 CF 1C 6A E8 4A A3 74 DE D5 15 5D 6A 88 } // Filesystem.dll 
        
    condition:
        any of them
}
