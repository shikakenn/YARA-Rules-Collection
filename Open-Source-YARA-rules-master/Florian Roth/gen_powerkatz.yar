
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-02-05
    Identifier: Powerkatz
*/

rule Powerkatz_DLL_Generic {
    meta:
        id = "2chhonssHUEK1vu6a6Qp8q"
        fingerprint = "v1_sha256_6daae96b3f44fd178a6b059acc4b786dc92ff20fb4cda43162894c39594788c7"
        version = "1.0"
        score = 80
        date = "2016-02-05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
        category = "INFO"
        reference = "PowerKatz Analysis"
        super_rule = 1
        hash1 = "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
        hash2 = "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
        hash3 = "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"

    strings:
        $s1 = "%3u - Directory '%s' (*.kirbi)" fullword wide
        $s2 = "%*s  pPublicKey         : " fullword wide
        $s4 = "<3 eo.oe ~ ANSSI E>" fullword wide
        $s5 = "\\*.kirbi" fullword wide

        $c1 = "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
        $c2 = "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them
}
