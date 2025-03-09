rule TRITON_ICS_FRAMEWORK
{
    meta:
        id = "2pUklSa5OtAlXUcLEjKCk"
        fingerprint = "v1_sha256_dfe50a71f8e1d53a141317982a19a3d68f54e36296c5d90d39c21c5d7cfa7bff"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "nicholas.carr @itsreallynick"
        description = "TRITON framework recovered during Mandiant ICS incident response"
        category = "INFO"
        reference = "https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html"
        md5 = "0face841f7b2953e7c29c064d6886523"

      strings:
          $python_compiled = ".pyc" nocase ascii wide
          $python_module_01 = "__module__" nocase ascii wide
          $python_module_02 = "<module>" nocase ascii wide
          $python_script_01 = "import Ts" nocase ascii wide
          $python_script_02 = "def ts_" nocase ascii wide  

          $py_cnames_01 = "TS_cnames.py" nocase ascii wide
          $py_cnames_02 = "TRICON" nocase ascii wide
          $py_cnames_03 = "TriStation " nocase ascii wide
          $py_cnames_04 = " chassis " nocase ascii wide  

          $py_tslibs_01 = "GetCpStatus" nocase ascii wide
          $py_tslibs_02 = "ts_" ascii wide
          $py_tslibs_03 = " sequence" nocase ascii wide
          $py_tslibs_04 = /import Ts(Hi|Low|Base)[^:alpha:]/ nocase ascii wide
          $py_tslibs_05 = /module\s?version/ nocase ascii wide
          $py_tslibs_06 = "bad " nocase ascii wide
          $py_tslibs_07 = "prog_cnt" nocase ascii wide  

          $py_tsbase_01 = "TsBase.py" nocase ascii wide
          $py_tsbase_02 = ".TsBase(" nocase ascii wide 
         
          $py_tshi_01 = "TsHi.py" nocase ascii wide
          $py_tshi_02 = "keystate" nocase ascii wide
          $py_tshi_03 = "GetProjectInfo" nocase ascii wide
          $py_tshi_04 = "GetProgramTable" nocase ascii wide
          $py_tshi_05 = "SafeAppendProgramMod" nocase ascii wide
          $py_tshi_06 = ".TsHi(" ascii nocase wide  

          $py_tslow_01 = "TsLow.py" nocase ascii wide
          $py_tslow_02 = "print_last_error" ascii nocase wide
          $py_tslow_03 = ".TsLow(" ascii nocase wide
          $py_tslow_04 = "tcm_" ascii wide
          $py_tslow_05 = " TCM found" nocase ascii wide  

          $py_crc_01 = "crc.pyc" nocase ascii wide
          $py_crc_02 = "CRC16_MODBUS" ascii wide
          $py_crc_03 = "Kotov Alaxander" nocase ascii wide
          $py_crc_04 = "CRC_CCITT_XMODEM" ascii wide
          $py_crc_05 = "crc16ret" ascii wide
          $py_crc_06 = "CRC16_CCITT_x1D0F" ascii wide
          $py_crc_07 = /CRC16_CCITT[^_]/ ascii wide  

          $py_sh_01 = "sh.pyc" nocase ascii wide  

          $py_keyword_01 = " FAILURE" ascii wide
          $py_keyword_02 = "symbol table" nocase ascii wide  

          $py_TRIDENT_01 = "inject.bin" ascii nocase wide
          $py_TRIDENT_02 = "imain.bin" ascii nocase wide  

      condition:
          2 of ($python_*) and 7 of ($py_*) and filesize < 3MB
}
