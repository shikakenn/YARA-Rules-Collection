rule php_shell_U34 {
    meta:
        id = "5Tqwub2R85lOxSmwGQ7LpV"
        fingerprint = "v1_sha256_13a83205efd68407d93f8d0c9c730895e6be9066a57c85f22ee20878710abc2a"
        version = "1.0"
        date = "2017/01/25"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Monty St John"
        description = "Web Shell - file ans.php"
        category = "INFO"
        hash = "5be3b1bc76677a70553a66575f289a0a"
        company = "Cyberdefenses, inc."

strings:
$a = "'\".((strpos(@$_POST['"
$b = "'],\"\\n\")!==false)?'':htmlspecialchars(@$_POST['"
$c = "'],ENT_QUOTES)).\"';"
$d = "posix_getpwuid"
condition:
  all of them 
}
