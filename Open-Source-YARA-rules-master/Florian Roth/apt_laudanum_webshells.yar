/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-22
    Identifier: Laudanum
*/

rule asp_file {
    meta:
        id = "KziX0gALuZi67bE6kKBiO"
        fingerprint = "v1_sha256_9ec19a994571f4d1b40b6d6af3fb6eb4c5004a6439b99863b50dae0262677263"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file file.asp"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "ff5b1a9598735440bdbaa768b524c639e22f53c5"

    strings:
        $s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
        $s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
        $s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "set folder = fso.GetFolder(path)" fullword ascii
        $s6 = "Set file = fso.GetFile(filepath)" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 30KB and 5 of them
}

rule php_killnc {
    meta:
        id = "I9PAblKnxXAegbr0Pnsfw"
        fingerprint = "v1_sha256_431a9a66f5d0e42856ca5716c2994c018f77cc338300abd71d94ffe7e75da3bf"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file killnc.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"

    strings:
        $s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
        $s3 = "<?php echo exec('killall nc');?>" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "<title>Laudanum Kill nc</title>" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
    condition:
        filesize < 15KB and 4 of them
}

rule asp_shell {
    meta:
        id = "7EE8z22kqa0VOMbP4axjwV"
        fingerprint = "v1_sha256_af9c5cf7125e1210761e720c5f30527ac6345b5029b087807309000a29b67f6e"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file shell.asp"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"

    strings:
        $s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "%ComSpec% /c dir" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "Server.ScriptTimeout = 180" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "cmd = Request.Form(\"cmd\")" fullword ascii /* PEStudio Blacklist: strings */
        $s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
        $s7 = "Dim wshell, intReturn, strPResult" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 15KB and 4 of them
}

rule settings {
    meta:
        id = "7NaO2YqV5bIM8jhMUsU59m"
        fingerprint = "v1_sha256_b02e293e659fa77257d0642c57e51d6ae712d9221ae295cf69bb845f68c650ee"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file settings.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"

    strings:
        $s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<li>Reverse Shell - " fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 13KB and all of them
}

rule asp_proxy {
    meta:
        id = "7g5I0WIobkVAF3iYUnNEnL"
        fingerprint = "v1_sha256_f53c97a2bf31f411b3220dc741b85d0edf96e9b92474f1abd5ac443be6b92897"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file proxy.asp"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "51e97040d1737618b1775578a772fa6c5a31afd8"

    strings:
        $s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
        $s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii /* PEStudio Blacklist: strings */
        $s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 50KB and all of them
}

rule cfm_shell {
    meta:
        id = "6uUJ3IDp2tRoZPCqDWv5X4"
        fingerprint = "v1_sha256_961eb398422e3c528b886c150f11dcb8a6832f0ea48e20ddc381e1f2740bd0c6"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file shell.cfm"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "885e1783b07c73e7d47d3283be303c9719419b92"

    strings:
        $s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
    condition:
        filesize < 20KB and 2 of them
}

rule aspx_shell {
    meta:
        id = "3geKnjgRbBZQiUrZRu4fUK"
        fingerprint = "v1_sha256_b31c36f53d46e17b6d97e582e46c540928a386e2075b841f5c11b959a0c68462"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file shell.aspx"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"

    strings:
        $s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii /* PEStudio Blacklist: strings */
        $s2 = "remoteIp = Request.UserHostAddress;" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<form method=\"post\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 20KB and all of them
}

rule php_shell {
    meta:
        id = "7BPdXkntEGmPu0zkAmaMtw"
        fingerprint = "v1_sha256_dc798508434686bbcb4fa0bb47381252bfa0491b0987956fd4c5aa13b7f57810"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file shell.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"

    strings:
        $s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 40KB and all of them
}

rule php_reverse_shell {
    meta:
        id = "2AAZD6AXr6x0rNoICU1pSo"
        fingerprint = "v1_sha256_ea8e320abb57e0467db92271f7d36f144f85e04ce15cd9fa8d3f53dfa8d43929"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file php-reverse-shell.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"

    strings:
        $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 15KB and all of them
}

rule php_dns {
    meta:
        id = "7ekYhTIFr0mc3ZbGcOeQ6c"
        fingerprint = "v1_sha256_650eecc06f215ae6a15078c87d8a8c1597ca9e3d735eacd17b046a9d9deb6aa8"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file dns.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"

    strings:
        $s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "foreach (array_keys($types) as $t) {" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule WEB_INF_web {
    meta:
        id = "683lLrwNiTMPl4NMSkfkeB"
        fingerprint = "v1_sha256_b58bb63a5268812ed6a5d18c8da96b0fdae33e4802a2fba4964ab69e92517a16"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file web.xml"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"

    strings:
        $s1 = "<servlet-name>Command</servlet-name>" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule jsp_cmd {
    meta:
        id = "6ZoINOL7cLEmoc8GWa5R06"
        fingerprint = "v1_sha256_ab5b013a385549322bcb2811fa1a2d14b5633e2c41b9486b1e1c50c02437b8e6"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file cmd.war"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"

    strings:
        $s0 = "cmd.jsp}" fullword ascii
        $s1 = "cmd.jspPK" fullword ascii
        $s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */
        $s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */
        $s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */
    condition:
        uint16(0) == 0x4b50 and filesize < 2KB and all of them
}

rule laudanum {
    meta:
        id = "6yOFawMz1itGVtIMD4f6Vo"
        fingerprint = "v1_sha256_53caad87d22b5f13e5b7be8720baa1d436cc57d8062ec5d557df8524a2ccfb68"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file laudanum.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"

    strings:
        $s1 = "public function __activate()" fullword ascii
        $s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 5KB and all of them
}

rule php_file {
    meta:
        id = "73FOD7VmxKc9CFVcOKJiiV"
        fingerprint = "v1_sha256_85c14a9c8a6aece231b1cb6dcdd7ed39fdc6aced868c34557ee2e2204ce7007b"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file file.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"

    strings:
        $s1 = "$allowedIPs =" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
        $s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
    condition:
        filesize < 10KB and all of them
}

rule warfiles_cmd {
    meta:
        id = "4bjpJd6lgIvPuyuuyRpndt"
        fingerprint = "v1_sha256_64724b24d9f5b5d78e231ea8196abb609237cc430c49f6ceeb99c9684a904568"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file cmd.jsp"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "3ae3d837e7b362de738cf7fad78eded0dccf601f"

    strings:
        $s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
        $s4 = "String disr = dis.readLine();" fullword ascii
    condition:
        filesize < 2KB and all of them
}

rule asp_dns {
    meta:
        id = "15KD6Bj185LbLkGucS3Dtj"
        fingerprint = "v1_sha256_808e879238a0c24e975c260fc95c05c91bdc0f73553a241bd00f5bf7e6622639"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file dns.asp"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"

    strings:
        $s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "Response.Write command & \"<br>\"" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 21KB and all of them
}

rule php_reverse_shell_2 {
    meta:
        id = "4BBgYnJL4tCGDvMY33jCID"
        fingerprint = "v1_sha256_695dc565c273ed358f7d56526fa4956ba13b216d8897d0707e1660a82b745081"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools - file php-reverse-shell.php"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        hash = "025db3c3473413064f0606d93d155c7eb5049c42"

    strings:
        $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
        $s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 10KB and all of them
}

rule Laudanum_Tools_Generic {
    meta:
        id = "4nH2p3WKHJxqxxhvTI0paC"
        fingerprint = "v1_sha256_52c6d3be4fc91e8a61645886fa89bf78eddad51960702ff2ac83ec01d5d529ef"
        version = "1.0"
        date = "2015-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Laudanum Injector Tools"
        category = "INFO"
        reference = "http://laudanum.inguardians.com/"
        super_rule = 1
        hash0 = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
        hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
        hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
        hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
        hash4 = "f49291aef9165ee4904d2d8c3cf5a6515ca0794f"
        hash5 = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
        hash6 = "f32b9c2cc3a61fa326e9caebce28ef94a7a00c9a"
        hash7 = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
        hash8 = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
        hash9 = "b50ae35fcf767466f6ca25984cc008b7629676b8"
        hash10 = "5570d10244d90ef53b74e2ac287fc657e38200f0"
        hash11 = "42bcb491a11b4703c125daf1747cf2a40a1b36f3"
        hash12 = "83e4eaaa2cf6898d7f83ab80158b64b1d48096f4"
        hash13 = "dec7ea322898690a7f91db9377f035ad7072b8d7"
        hash14 = "a2272b8a4221c6cc373915f0cc555fe55d65ac4d"
        hash15 = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
        hash16 = "43320dc23fb2ed26b882512e7c0bfdc64e2c1849"

    strings:
        $s1 = "***  laudanum@secureideas.net" fullword ascii
        $s2 = "*** Laudanum Project" fullword ascii
    condition:
        filesize < 60KB and all of them
}
