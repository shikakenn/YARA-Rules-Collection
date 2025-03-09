rule agent_tesla
{
    meta:
        id = "37qyF5wHEiNYP7odmt6vX9"
        fingerprint = "v1_sha256_3945754129dcc58e0abfd7485f5ff0c0afdd1078ae2cf164ca8f59a6f79db1be"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Stormshield"
        description = "Detecting HTML strings used by Agent Tesla malware"
        category = "INFO"
        reference = "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}
