/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


rule xbot007
{
    meta:
        id = "zUZGz1wnJi784RYHJihzp"
        fingerprint = "v1_sha256_4a36544942821f0e5eef7e6d08a8c6707eea205d764dd2c0b5485507b28ce2ad"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"

    strings:
        $a = "xbot007"

    condition:
        any of them
}
