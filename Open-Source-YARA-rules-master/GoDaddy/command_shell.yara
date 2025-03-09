
rule command_shell {
    meta:
        id = "1YiQjLZRIhEVNs6CZNW1H3"
        fingerprint = "v1_sha256_33f754b7f611fc7c5cfbca9e3c154263a2c4db9c7f3b0ff2a4ac3f598eebe830"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Microsoft Windows Command Shell"
        category = "INFO"
        Block = false
        Quarantine = false

    strings:
        $internal_error = "CMD Internal Error %s"
        $shell_open_command = "\\Shell\\Open\\Command" ascii wide
        $mklink = "ENDLOCAL" ascii wide
        $errorlevel = "ERRORLEVEL" ascii wide
        $cmdextversion = "CMDEXTVERSION" ascii wide
        $dpath = "DPATH" ascii wide
        $color = "COLOR" ascii wide
        $chdir = "CHDIR" ascii wide
        $pushd = "PUSHD" ascii wide
        $ftype = "FTYPE" ascii wide
        $erase = "ERASE" ascii wide
        $defined = "DEFINED" ascii wide
        $prompt = "PROMPT" ascii wide
        $setlocal = "SETLOCAL" ascii wide

    condition:
        IsPeFile and all of them
}

