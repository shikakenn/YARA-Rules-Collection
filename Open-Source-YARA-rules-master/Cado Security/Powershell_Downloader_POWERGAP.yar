rule Powershell_Downloader_POWERGAP {
    meta:
        id = "2j9Ig8Vm8jOh8jHVvfbFbk"
        fingerprint = "v1_sha256_a9ef1d04ca921f285e973f6abcb2b355eae110678da866e3b6499aa0318338fd"
        version = "1.0"
        date = "2022-04-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mmuir@cadosecurity.com"
        description = "Detects POWERGAP downloader used against Ukrainian ICS"
        category = "INFO"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        license = "Apache License 2.0"

    strings:
        $a = "Start-work" ascii
        $b = "$GpoGuid" ascii
        $c = "$SourceFile" ascii
        $d = "$DestinationFile" ascii
        $e = "$appName" ascii
    $f = "LDAP://ROOTDSE" ascii
    $g = "GPT.INI" ascii
    $h = "Get-WmiObject" ascii
    condition:
        5 of them
}
