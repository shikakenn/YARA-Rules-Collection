rule Doki_Attack
{
    meta:
        id = "6HOxka8NaPPPKmlpaVnUJy"
        fingerprint = "v1_sha256_1427e17cf15c9cf2581ecbdbeae32080492e47c378b3fb9155d82c61c35b8297"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
    
        $a1 = /curl --retry 3 -m 60 -o \/tmp\w{6}\/tmp\/tmp.{37}.*\\{3}\"http:\/{2}.*\.ngrok\.io[\s\S]*\\{3}\";/ nocase
        $a2 = /rm -rf \/tmp\w{6}\/etc\/crontab;/ nocase
        $s1 = /echo \\{3}\"(\*\s){4}\* root sh \/tmp\/tmp.*\\{3}\" \\{2}u003e\/tmp\w{6}\/etc\/cron.d\/1m;/ nocase
        $s2 = /echo \\{3}\"(\*\s){4}\* root sh \/tmp\/tmp\w*\\{3}\" \\{2}u003e\/tmp\w{6}\/etc\/crontab;/ nocase
        $s3 = /chroot \/tmp\w{6} sh -c \\{3}\"cron \|\| crond/ nocase
    condition:
       all of them
}
