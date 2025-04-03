private rule APT9002Code : APT9002 Family 
{
    meta:
        id = "7PVTJmiHm6YRdrrdtcz9lW"
        fingerprint = "v1_sha256_9048f093051e8da72071beb5356a0de62d53047bd0feb3987b36e3f026b1c0cb"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "9002 code features"
        category = "INFO"

    strings:
        // start code block
        $ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
        // decryption from other variant with multiple start threads
        $ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }
  
    condition:
        any of them
}

private rule APT9002Strings : APT9002 Family
{
    meta:
        id = "354OvuhzMbgaJ2z5Gpef1u"
        fingerprint = "v1_sha256_41386c01c09c47ef0d3615a81e1eff7c366d5be030c10f5b03d897c6a41a9506"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "9002 Identifying Strings"
        category = "INFO"

    strings:
        $ = "POST http://%ls:%d/%x HTTP/1.1"
        $ = "%%TEMP%%\\%s_p.ax" wide ascii
        $ = "%TEMP%\\uid.ax" wide ascii
        $ = "%%TEMP%%\\%s.ax" wide ascii
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
        $ = "sysinfo\x00sysbin01"
        $ = "\\FlashUpdate.exe"
        
    condition:
       any of them
}

rule APT9002 : Family
{
    meta:
        id = "6WxJuxCBPZsLaKWIOrmOnG"
        fingerprint = "v1_sha256_4fe9011e7d0c6162c9beb7a99fb0b449a15966a3a7273d700be9253feb34aa9d"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "9002"
        category = "INFO"

    condition:
        APT9002Code or APT9002Strings
}
