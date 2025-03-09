/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-04-26
    Identifier: regsvr32 issue
*/

/* Rule Set ----------------------------------------------------------------- */

rule SCT_Scriptlet_in_Temp_Inet_Files {
    meta:
        id = "5qZ31mq0hghZjjbCNApvNI"
        fingerprint = "v1_sha256_f523f1e5774a1e8e0c0a6c9419074a7b494fe398d6f73b1f4a3742264ec79543"
        version = "1.0"
        date = "2016-04-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a scriptlet file in the temporary Internet files (see regsvr32 AppLocker bypass)"
        category = "INFO"
        reference = "http://goo.gl/KAB8Jw"

    strings:
        $s1 = "<scriptlet>" fullword ascii nocase
        $s2 = "ActiveXObject(\"WScript.Shell\")" ascii
    condition:
        ( uint32(0) == 0x4D583F3C or uint32(0) == 0x6D78F3C ) /* <?XM or <?xm */
        and $s1 and $s2
        and filepath contains "Temporary Internet Files"
}
