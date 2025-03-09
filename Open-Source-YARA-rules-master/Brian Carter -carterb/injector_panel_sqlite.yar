rule INJECTOR_PANEL_SQLITE

{
    meta:
        id = "4UPe4yddPOdWZ4XTcfJ6VK"
        fingerprint = "v1_sha256_b6c63ee0cc96ec3033086c2efd1bc915d8ea6789578eaea01565ba18c9d9b877"
        version = "1.0"
        modified = "August 14, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find sqlite dbs used with tables inject panel"
        category = "INFO"

    strings:
        $magic = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }
        $txt1 = "CREATE TABLE Settings"
        $txt2 = "CREATE TABLE Jabber"
        $txt3 = "CREATE TABLE Users"
        $txt4 = "CREATE TABLE Log"
        $txt5 = "CREATE TABLE Fakes"
        $txt6 = "CREATE TABLE ATS_links"

    condition:
        $magic at 0 and all of ($txt*)

}
