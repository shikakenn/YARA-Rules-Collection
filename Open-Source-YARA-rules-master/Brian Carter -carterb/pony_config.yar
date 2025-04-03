rule config_php

{
    meta:
        id = "38UiZPkC4xUAUP3F17JphM"
        fingerprint = "v1_sha256_adeb2709dcdcbbbe249036d4667a353d50ca7694a3c6849f6e992926ce0fa03c"
        version = "1.0"
        modified = "March 31, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find config.php files that have details for the db"
        category = "INFO"

    strings:
        $txt1 = "$mysql_host ="
        $txt2 = "$mysql_user ="
        $txt3 = "mysql_pass ="
        $txt4 = "mysql_database ="
        $txt5 = "global_filter_list"
        $txt6 = "white-list"
        $php1 = "<?php"
        
    condition:
        $php1 at 0 and all of ($txt*)
        
}
