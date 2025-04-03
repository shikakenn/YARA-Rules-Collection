import "pe"
import "math"

rule apt_ProjectSauron_pipe_backdoor  {
    meta:
        id = "5lb412sAc5hoWA8stpcOoR"
        fingerprint = "v1_sha256_72f6c6fa65f15e4bab18a0f9d5b5b2f571b21d70c7ff306020784ce604a2e0a5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect ProjectSauron pipe backdoors"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

    strings:
        $a1 = "CreateNamedPipeW" fullword ascii
        $a2 = "SetSecurityDescriptorDacl" fullword ascii
        $a3 = "GetOverlappedResult" fullword ascii
        $a4 = "TerminateThread" fullword ascii
        $a5 = "%s%s%X" fullword wide
    condition:
        uint16(0) == 0x5A4D
        and (all of ($a*))
        and filesize < 100000
}

rule apt_ProjectSauron_encrypted_LSA  {
    meta:
        id = "5gW6cdCA8jW5XiLC6Wu59T"
        fingerprint = "v1_sha256_96c3a536ea819b9e06e20255efdf9ab41c380f2f757b891d0a45d0ce80adc936"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect ProjectSauron encrypted LSA samples"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

strings:
    $a1 = "EFEB0A9C6ABA4CF5958F41DB6A31929776C643DEDC65CC9B67AB8B0066FF2492" fullword ascii
    $a2 = "\\Device\\NdisRaw_" fullword ascii
    $a3 = "\\\\.\\GLOBALROOT\\Device\\{8EDB44DC-86F0-4E0E-8068-BD2CABA4057A}" fullword wide
    $a4 = "Global\\{a07f6ba7-8383-4104-a154-e582e85a32eb}" fullword wide
    $a5 = "Missing function %S::#%d" fullword wide
    $a6 = {8945D08D8598FEFFFF2BD08945D88D45BC83C20450C745C0030000008975C48955DCFF55FC8BF88D8F0000003A83F90977305333DB53FF15}
    $a7 = {488D4C24304889442450488D452044886424304889442460488D4520C7442434030000002BD848897C243844896C244083C308895C246841FFD68D880000003A8BD883F909772DFF}
condition:
    uint16(0) == 0x5A4D
    and (any of ($a*) or
    (
        pe.exports("InitializeChangeNotify") and
        pe.exports("PasswordChangeNotify") and
        math.entropy(0x400, filesize) >= 7.5
    ))
    and filesize < 1000000
}

rule apt_ProjectSauron_encrypted_SSPI  {
    meta:
        id = "r6hEPT6nLp15vxOMwJynu"
        fingerprint = "v1_sha256_99d7444ffc45076e97ac3f5c9909ae26a927bbdcfef274d12d162c59e8113d65"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect encrypted ProjectSauron SSPI samples"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

condition:
    uint16(0) == 0x5A4D and
    filesize < 1000000 and
    pe.exports("InitSecurityInterfaceA") and
    pe.characteristics & pe.DLL and
    (pe.machine == pe.MACHINE_AMD64 or pe.machine == pe.MACHINE_IA64) and
    math.entropy(0x400, filesize) >= 7.5
}

rule apt_ProjectSauron_MyTrampoline  {
    meta:
        id = "6TX7xgW5eke4KdLUnNthcf"
        fingerprint = "v1_sha256_0bd98815fbf6e82cf477e4f4f98360a4c132b2b21e2e5991f6c10903bd4df52b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect ProjectSauron MyTrampoline module"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

strings:
    $a1 = ":\\System Volume Information\\{" wide
    $a2 = "\\\\.\\PhysicalDrive%d" wide
    $a3 = "DMWndClassX%d"

    $b1 = "{774476DF-C00F-4e3a-BF4A-6D8618CFA532}" ascii wide
    $b2 = "{820C02A4-578A-4750-A409-62C98F5E9237}" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 5000000 and
    (all of ($a*) or any of ($b*))
}

rule apt_ProjectSauron_encrypted_container  {
    meta:
        id = "1vHpJAwVz2PFkKQ2jtz13Z"
        fingerprint = "v1_sha256_9b36f2f1161fd2ff856db520efca8648892656b7a2587dce1a7445af4fbba013"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect ProjectSauron samples encrypted container"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

strings:

    $vfs_header = {02 AA 02 C1 02 0?}
    $salt = {91 0A E0 CC 0D FE CE 36 78 48 9B 9C 97 F7 F5 55}

condition:
    uint16(0) == 0x5A4D
    and ((@vfs_header < 0x4000) or $salt) and
    math.entropy(0x400, filesize) >= 6.5 and
    (filesize > 0x400) and filesize < 10000000
}

rule apt_ProjectSauron_encryption  {
    meta:
        id = "OaruZTyCrLKp8RkBkHxvO"
        fingerprint = "v1_sha256_ae3a681b0cf9ed93d25fa35982daab48c460ba9737eb643ba28a972ea3a7b401"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect ProjectSauron string encryption"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

strings:

    $a1 = {81??02AA02C175??8B??0685}
    $a2 = {918D9A94CDCC939A93939BD18B9AB8DE9C908DAF8D9B9BBE8C8C9AFF}
    $a3 = {803E225775??807E019F75??807E02BE75??807E0309}

condition:
    filesize < 5000000 and
    any of ($a*)
}

rule apt_ProjectSauron_generic_pipe_backdoor {
    meta:
        id = "cK1rOvmWMKg5qcec8W5Gs"
        fingerprint = "v1_sha256_ec8a311ec1bd98532c278f72c77e58edb5890db940046dfcd14adf1495e9de1e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect ProjectSauron generic pipe backdoors"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

strings:
    $a = { C7 [2-3] 32 32 32 32 E8 }
    $b = { 42 12 67 6B }
    $c = { 25 31 5F 73 }
    $d = "rand"
    $e = "WS2_32"

condition:
    uint16(0) == 0x5A4D and
    (all of them) and
    filesize < 400000
}
