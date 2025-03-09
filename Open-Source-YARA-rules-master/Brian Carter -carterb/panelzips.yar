rule chinapic_zip

{

    meta:
        id = "4lwJb86PEgAkOPTnCqnrMY"
        fingerprint = "v1_sha256_e57e1f62e35a12d26b38dce3abff5dfb21dcc1c828cef064549266b675e8adce"
        version = "1.0"
        modified = "March 31, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find zip archives of pony panels that have china.jpg"
        category = "INFO"

    strings:
        $txt1 = "china.jpg"
        $txt2 = "config.php"
        $txt3 = "setup.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule diamondfox_zip

{

    meta:
        id = "107Ntn5aiL5B31Ch2fF4FP"
        fingerprint = "v1_sha256_8eadd8da216a007300952a18c5010677dde49b145e1d24d83618563460d1870b"
        version = "1.0"
        modified = "March 31, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find zip archives of panels"
        category = "INFO"

    strings:
        $txt1 = "gate.php"
        $txt2 = "install.php"
        $txt3 = "post.php"
        $txt4 = "plugins"
        $txt5 = "statistics.php"
        $magic = { 50 4b 03 04 }
        $not1 = "joomla" nocase
        
    condition:
        $magic at 0 and all of ($txt*) and not any of ($not*)
        
}

rule keybase_zip

{

    meta:
        id = "1B7p2nwIPwKmgXNJeHAMrH"
        fingerprint = "v1_sha256_98889cfe0c23225f0d1b73dde8ef3d62a6d62b6c40a750951b995d636908e51c"
        version = "1.0"
        modified = "March 31, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find zip archives of panels"
        category = "INFO"

    strings:
        $txt1 = "clipboard.php"
        $txt2 = "config.php"
        $txt3 = "create.php"
        $txt4 = "login.php"
        $txt5 = "screenshots.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule zeus_zip

{

    meta:
        id = "3Bi6Z62uZfcTwdylmEYRFX"
        fingerprint = "v1_sha256_dfeeadc337e47f5e4990d695fa0be6e7030157d3c318734650564297097f018c"
        version = "1.0"
        modified = "April 19, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find zip archives of panels"
        category = "INFO"

    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "botnet_bots.php"
        $txt4 = "botnet_scripts.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule atmos_zip

{

    meta:
        id = "s6QghKxxQDRMIB43rr1Sk"
        fingerprint = "v1_sha256_f104c538fb02e7e48ceb0e0acd13593dff310284451504ba93d8cf1e2e55bf27"
        version = "1.0"
        modified = "April 27, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find zip archives of panels"
        category = "INFO"

    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "api.php"
        $txt4 = "file.php"
        $txt5 = "ts.php"
        $txt6 = "index.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule new_pony_panel

{

    meta:
        id = "2UqMXwfreUHFrFULBVCUCq"
        fingerprint = "v1_sha256_76209c0a9c95fbe0071c62ac2a2189bc1244aef0bcc29dd9b13cce9a66882bd0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "New Pony Zips"
        category = "INFO"

    strings:
        $txt1 = "includes/design/images/"
        $txt2 = "includes/design/style.css"
        $txt3 = "admin.php"
        $txt4 = "includes/design/images/user.png"
        $txt5 = "includes/design/images/main_bg.gif"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
