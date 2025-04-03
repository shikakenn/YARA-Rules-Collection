rule UNC5221_WIREFIRE_Webshell
{
    meta:
        id = "4rQ7coxSr86MaDXmJowAlF"
        fingerprint = "v1_sha256_489ba4427863c91f22e5fe7094dafe0f9548b5692c90dbd7aad6d671933db9fe"
        version = "1.0"
        date = "2024-01-19"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "QuoIntelligence"
        description = "Detects the web shell WIREFIRE tracked by Mandiant and similar variants using common pack / unpack methods"
        category = "INFO"
        report = "HTTPS://QUOINTELLIGENCE.EU/2024/01/UNC5221-UNREPORTED-AND-UNDETECTED-WIREFIRE-WEB-SHELL-VARIANT/"

strings:
   $s1 = "zlib.decompress(aes.decrypt(base64.b64decode(" ascii
   $s2 = "from Cryptodome.Cipher import AES" ascii
   $p1 = "aes.encrypt(t+('\\x00'*(16-len(t)%16))" ascii
condition:
   filesize < 10KB and all of ($s*) or any of ($p*)
}
