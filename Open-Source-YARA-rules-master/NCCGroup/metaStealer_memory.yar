rule metaStealer_memory {
    meta:
        id = "7Du0JnXZPcSUJ2MXWwNCGw"
        fingerprint = "v1_sha256_68bed59acaede1e0bb80bd5490b74593c373df83762d5fd160defca3c4bac46a"
        version = "1.0"
        date = "2022-04-29"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Peter Gurney"
        description = "MetaStealer Memory"
        category = "INFO"
        reference = "https://research.nccgroup.com/2022/05/20/metastealer-filling-the-racoon-void/"

   strings:
      $str_c2_parse = {B8 56 55 55 55 F7 6D C4 8B C2 C1 E8 1F 03 C2 8B 55 C0 8D 04 40 2B 45 C4}
      $str_filename = ".xyz -newname hyper-v.exe" fullword wide
      $str_stackstring = {FF FF FF C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 0F EF}
   condition:
      uint16(0) == 0x5a4d and
      2 of ($str_*)
}
