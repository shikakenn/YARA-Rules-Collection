rule mal_injection_function_stomping: RELEASED MALWARE LOADER TA0005 T1055 {
    meta:
        id = "6unc0fRxDDzQvOeZ2Vitmb"
        fingerprint = "v1_sha256_2c324eab711299dbf5a2b0c2c4806253cf17504f1fc30c03887693a2bf1a9fe3"
        version = "1.1"
        date = "2022-01-25"
        modified = "2023-03-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects suspicious strings related to the FunctionStomping PoC by Ido Veltzman"
        category = "MALWARE"
        malware = "LOADER"
        mitre_att = "T1055"
        reference = "https://github.com/Idov31/FunctionStomping/blob/9ed837b51616147c0b36235583c9d26d72e3d3cb/header/functionstomping.hpp"
        hash = "37cf2f4a421ff8feb097f62eefcca647bc50acc571f7f620885d10741a2d09a5"
        first_imported = "2023-02-23"

    strings:
        $stomp_err      = "The function name is misspelled or the function is unstompable"  ascii wide fullword
        $stomp_ok       = "Successfuly stomped the function"                                ascii wide fullword
        $ok_func_base   = "Got function base"                                               ascii wide fullword
        $ok_perms       = "Changed protection to WCX instead of RWX"                        ascii wide fullword
        $err_stomp_size = "Cannot write more than 4096 bytes"                               ascii wide fullword
        $err_stomp      = "Failed to overwrite function"                                    ascii wide fullword

    condition:
        any of ($stomp_*) or 4 of them
}
