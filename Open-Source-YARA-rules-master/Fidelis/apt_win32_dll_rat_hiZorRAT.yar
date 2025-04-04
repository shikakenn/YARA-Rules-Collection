rule apt_win32_dll_rat_hiZorRAT
{             
    meta:
        id = "6PB0HVACoX3acMh7033bPO"
        fingerprint = "v1_sha256_74ff2c5fc997de6cd619932df69e9f9549ca85697b2b11fa0eb9520dc04b93aa"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
        hash2 = "d9821468315ccd3b9ea03161566ef18e"
        hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"
        ref1 = "http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html"
        ref2 = "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf"

               strings:
                             
                              // Part of the encoded User-Agent = Mozilla
                              $ = { c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 } 
                             
                              // XOR to decode User-Agent after string stacking 0x10001630
                              $ = { 66 [7] 0d 40 83 ?? ?? 7c ?? } 
                             
                              // XOR with 0x2E - 0x10002EF6
                             
                              $ = { 80 [2] 2e 40 3b ?? 72 ?? } 
                             
                              $ = "CmdProcessExited" wide ascii
                              $ = "rootDir" wide ascii
                              $ = "DllRegisterServer" wide ascii
                              $ = "GetNativeSystemInfo" wide ascii
                              $ = "%08x%08x%08x%08x" wide ascii
                             
               condition:
                              (uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f) and (all of them)
}
