rule IQY_File
{
    meta:
        id = "2VxcnVsOfyEs93ioonVwEv"
        fingerprint = "v1_sha256_19180d7e8092612954f42f5248c0efbed331436c41914551b444f89c0d0179e0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "InQuest Labs"
        Website = "http://blog.inquest.net/blog/2018/08/23/hunting-iqy-files-with-yara/"
        Description = "Detects all Excel IQY files by identifying the WEB 'magic' on the first line and also includes any URL."
        Severity = "0"

   strings:
        /* match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
        $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /* match any http or https URL within the file */
        $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

    condition:
        $web at 0 and $url
}
