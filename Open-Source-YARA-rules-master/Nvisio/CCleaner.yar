// YARA rules compromised CCleaner
// NVISO 2017/09/18
// http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html
 
import "hash"
 
rule ccleaner_compromised_installer { 
    meta:
        id = "6xnkF54gTsAwuYk2SYZ1Hi"
        fingerprint = "v1_sha256_bbc32438c6fc564a6562446b9f4515897aa2cbaa818b8dafdde3305bb3546b2b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NVISIO"
        description = "NA"
        category = "INFO"
        reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"

    condition:
        filesize == 9791816 and hash.sha256(0, filesize) == "1a4a5123d7b2c534cb3e3168f7032cf9ebf38b9a2a97226d0fdb7933cf6030ff"
}
 
rule ccleaner_compromised_application {
    meta:
        id = "7aKgQnvSEFX3zE6JxzfEc4"
        fingerprint = "v1_sha256_367789ac2fa124e1a0bd59b191daabe9f3d2e372328851a4cbcc31aa16383d06"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NVISIO"
        description = "NA"
        category = "INFO"
        reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"

    condition:
        filesize == 7781592 and hash.sha256(0, filesize) == "36b36ee9515e0a60629d2c722b006b33e543dce1c8c2611053e0651a0bfdb2e9" or
        filesize == 7680216 and hash.sha256(0, filesize) == "6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9"
}
 
rule ccleaner_compromised_pdb {
    meta:
        id = "1o0bvVJm3WYgSGnoKg5kaR"
        fingerprint = "v1_sha256_f23e2c6f81a4f2fe19b8b83f0f2d4bfc6c05f15b9b04bdf28c0173b65844acb6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NVISIO"
        description = "NA"
        category = "INFO"
        reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"

    strings:
        $a = "s:\\workspace\\ccleaner\\branches\\v5.33\\bin\\CCleaner\\Release\\CCleaner.pdb" 
        $b = "s:\\workspace\\ccleaner\\branches\\v5.33\\bin\\CCleaner\\ReleaseTV\\CCleaner.pdb" 
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and ($a or $b)
}
