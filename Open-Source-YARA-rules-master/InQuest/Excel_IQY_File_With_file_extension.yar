rule IQY_File_With_Pivot_Extension_URL
{
    meta:
        id = "3R94PqjRnbOEVbwfI9ohy4"
        fingerprint = "v1_sha256_02d38bebb1076a8119edb2711e39a2a3c104d193ab95958992f482567ad78dcc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "InQuest Labs"
        Reference = "http://blog.inquest.net/blog/2018/08/23/hunting-iqy-files-with-yara/"
        Description = "Detect Excel IQY files with URLs that contain commonly used malicious file extensions that may act as a pivot to a secondary stage."
        Severity = "9"

    strings:
        /*
           match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
         $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /*
            generic URL to direct download a file containing a potentially malicious extension.
            File extensions were decided based upon common extensions seen in the wild
            The extension list can be expanded upon as new information comes available from matches
            on the Stage 1 or Stage 2 signatures
         */

        $url = /https?:\/\/[\w\.\/]+\.(scr|exe|hta|vbs|ps1|bat|dat|rar|zip|ace)/ nocase

    condition:
        $web at 0 and $url
}
