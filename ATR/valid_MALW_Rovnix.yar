rule rovnix_downloader
{
    meta:
        id = "3G4qI7gfdPeVyO8mViKPTG"
        fingerprint = "v1_sha256_52cde40c95436129b7d48b4bd5e78b66deb84fdc84a76cc9ac72f24e0777e540"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Intel Security"
        description = "Rovnix downloader with sinkhole checks"
        category = "INFO"
        reference = "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/"
        rule_version = "v1"
        malware_family = "Downloader:W32/Rovnix"
        actor_group = "Unknown"

    strings:

            $sink1= "control"
            $sink2 = "sink"
            $sink3 = "hole"
            $sink4= "dynadot"
            $sink5= "block"
            $sink6= "malw"
            $sink7= "anti"
            $sink8= "googl"
            $sink9= "hack"
            $sink10= "trojan"
            $sink11= "abuse"
            $sink12= "virus"
            $sink13= "black"
            $sink14= "spam"
            $boot= "BOOTKIT_DLL.dll"
            $mz = { 4D 5A }

    condition:
    
        $mz in (0..2) and
        all of ($sink*) and
        $boot
}
