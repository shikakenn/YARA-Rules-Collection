rule Windows_Hacktool_SharpWMI_a67d6fe5 {
    meta:
        id = "46QS1kslbVpgdO4pf38toR"
        fingerprint = "v1_sha256_de8749951ece8d4798ade4661d531515e12edf8e8606ddc330000d847a66a26c"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpWMI"
        reference_sample = "2134a5e1a5eece1336f831a7686c5ea3b6ca5aaa63ab7e7820be937da0678e15"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide nocase
        $str0 = "powershell -w hidden -nop -c \"$e=([WmiClass]'{0}:{1}').Properties['{2}'].Value;[IO.File]::WriteAllBytes('{3}',[Byte[]][Int[]]($e-split','))\"" ascii wide
        $str1 = "powershell -w hidden -nop -c \"iex($env:{0})\"" ascii wide
        $str2 = "SELECT * FROM Win32_Process" ascii wide
        $str3 = "DOWNLOAD_URL" ascii wide
        $str4 = "TARGET_FILE" ascii wide
        $str5 = "SELECT Enabled,DisplayName,Action,Direction,InstanceID from MSFT_NetFirewallRule WHERE Enabled=1" ascii wide
        $print_str0 = "This may indicate called SharpWMI did not invoked WMI using elevated/impersonated token." ascii wide
        $print_str1 = "[+] Attempted to terminate remote process ({0}). Returned: {1}" ascii wide
    condition:
        $guid or (all of ($str*) and 1 of ($print_str*))
}

