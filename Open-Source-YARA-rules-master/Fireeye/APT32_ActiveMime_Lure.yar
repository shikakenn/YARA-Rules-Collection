rule APT32_ActiveMime_Lure{
    meta:
        id = "6jd6wMtwDwrImEAllqkcV0"
        fingerprint = "v1_sha256_37482df03954404c29dffcc677072ad0ed0dd90fec6eb850d00c542b3ca9ae2e"
        version = "1.0"
        date = "2017-03-02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Ian Ahl (@TekDefense) and Nick Carr (@ItsReallyNick)"
        description = "Developed to detect APT32 (OceanLotus Group phishing lures used to target Fireeye Customers in 2016 and 2017"
        category = "INFO"
        reference = "https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html"
        filetype = "MIME entity"

    strings:
        $a1 = "office_text" wide ascii
        $a2 = "schtasks /create /tn" wide ascii
        $a3 = "scrobj.dll" wide ascii
        $a4 = "new-object net.webclient" wide ascii
        $a5 = "GetUserName" wide ascii
        $a6 = "WSHnet.UserDomain" wide ascii
        $a7 = "WSHnet.UserName" wide ascii
    condition:
        4 of them
}
