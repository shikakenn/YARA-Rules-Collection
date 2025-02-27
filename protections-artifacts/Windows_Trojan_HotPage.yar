rule Windows_Trojan_HotPage_414f235f {
    meta:
        id = "2TwFT7MZPVoFTxakFFGD57"
        fingerprint = "v1_sha256_cfa0036b22a83a5396b3f9014511720071246a775053ad493791ebc1212400f2"
        version = "1.0"
        date = "2024-07-18"
        modified = "2024-07-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.HotPage"
        reference_sample = "b8464126b64c809b4ab47aa91c5f322ce2c0ae4fd668a43de738a5caa7567225"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $SpcSpOpusInfo = { 30 48 A0 1A 80 18 6E 56 53 17 76 FE 7F 51 7F 51 7E DC 79 D1 62 80 67 09 96 50 51 6C 53 F8 }
        $s1 = "\\Device\\KNewTableBaseIo"
        $s2 = "Release\\DwAdsafeLoad.pdb"
        $s3 = "RedDriver.pdb"
        $s4 = "Release\\DwAdSafe.pdb"
        $s5 = "[%s] Begin injecting Broser pid=[%d]"
        $s6 = "[%s] ADDbrowser PID ->[%d]"
    condition:
        $SpcSpOpusInfo or 2 of ($s*)
}

