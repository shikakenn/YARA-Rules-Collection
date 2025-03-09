rule potential_CVE_2017_11882
{
    meta:
        id = "Es6v9dl44L2uxFjnjqBVX"
        fingerprint = "v1_sha256_82c8a9e1f67b829d1d054a630e0c80e19466a721d0a545b8a2e72caded50aefb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "ReversingLabs"
        description = "NA"
        category = "INFO"
        reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"

    strings:
        $docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }

        $equation1 = "Equation Native" wide ascii
        $equation2 = "Microsoft Equation 3.0" wide ascii

        $mshta = "mshta"
        $http  = "http://"
        $https = "https://"
        $cmd   = "cmd"
        $pwsh  = "powershell"
        $exe   = ".exe"

        $address = { 12 0C 43 00 }

    condition:
        $docfilemagic at 0 and any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}
