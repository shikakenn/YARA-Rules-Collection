rule apt_c16_win_wateringhole 
{
    meta:
        id = "7gZbDJcxMCNVixFpOugQbH"
        fingerprint = "v1_sha256_e866499ec77984f5bacf3f5e352393b63e0dd08fd8fd57b4990292a1dc7fbcbe"
        version = "1.0"
        date = "2015/01/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab"
        description = "Detects code from APT wateringhole"
        category = "INFO"
        reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $str1 = "function runmumaa()"
    $str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
    $str3 = "function MoSaklgEs7(k)"
  condition:
    any of ($str*)
}
