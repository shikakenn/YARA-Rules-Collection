rule xll_custom_builder
{
    meta:
        id = "3iYCVyqX4U35vgS4UuxAak"
        fingerprint = "v1_sha256_9f44cd990ca04cff3d4fac58cefd5f62383b9e59983685fe958947eb7771c1a0"
        version = "1.0"
        date = "2022-01-07"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "patrick.schlapfer@hp.com"
        description = "XLL Custom Builder"
        category = "INFO"
        reference = "https://threatresearch.ext.hp.com/how-attackers-use-xll-malware-to-infect-systems/"

  strings:
    $str1 = "xlAutoOpen"
    $str2 = "test"
    $op1 = { 4D 6B C9 00 }
    $op2 = { 4D 31 0E }
    $op3 = { 49 83 C6 08 }
    $op4 = { 49 39 C6 }

  condition:
    uint16(0) == 0x5A4D and all of ($str*) and all of ($op*) and filesize < 10KB
}
