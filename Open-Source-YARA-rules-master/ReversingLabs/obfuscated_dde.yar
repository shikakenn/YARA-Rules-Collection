rule obfuscated_dde
{
    meta:
        id = "1BBe2vKHN7eEuM1yThBiGJ"
        fingerprint = "v1_sha256_3611497e551b9fa8d26c685c52797570fee5c72d0353dd9a7524adb1fc74f577"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "ReversingLabs"
        description = "NA"
        category = "INFO"
        reference = "https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation"

    strings:

        $dde_command_1 = /[=+-]+[ 0-9A-Za-z_\"\&\^\-\=\/\+\(\x00]*(((c|C)[\x00]*(m|M)[\x00]*(d|D)[\x00]*\|)|((m|M)[\x00]*(s|S)[\x00]*(i|I|e|E)[\x00]*(e|E|x|X)[\x00]*(x|X|c|C)[\x00]*(e|E)[\x00]*(c|C|l|L)[\x00]*\|)|((r|R)[\x00]*(u|U|e|E)[\x00]*(n|N|g|G)[\x00]*(d|D|s|S)[\x00]*(l|L|v|V)[\x00]*(l|L|r|R)[\x00]*3[\x00]*2[0-9A-Za-z\x00]*\|)|((c|C)[\x00]*(e|E)[\x00]*(r|R)[\x00]*(t|T)[\x00]*(u|U)[\x00]*(t|T)[\x00]*(i|I)[\x00]*(l|L)[0-9A-Za-z\x00]*\|))[\x00]*\'/

    condition:
        $dde_command_1
}
