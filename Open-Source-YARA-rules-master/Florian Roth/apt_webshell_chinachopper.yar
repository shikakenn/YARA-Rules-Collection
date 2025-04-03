
rule ChinaChopper_Generic {
    meta:
        id = "6MqH101di16VSkUnLidid2"
        fingerprint = "v1_sha256_1d02083162b3567bc455c42c3d4616e6abf5bddb2cf621c3ee387087dfdedefb"
        version = "1.0"
        date = "2015/03/10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "China Chopper Webshells - PHP and ASPX"
        category = "INFO"
        reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"

    strings:
        $aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(RequestItem\[.{,100}unsafe/
        $php = /<?php.\@eval\(\$_POST./
    condition:
        1 of them
}
