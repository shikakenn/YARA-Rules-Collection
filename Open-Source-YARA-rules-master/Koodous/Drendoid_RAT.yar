/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Dendroid
{
    meta:
        id = "6qmAy7nQiDzPOoYKDFSw2x"
        fingerprint = "v1_sha256_96a28d1a606453b8f5490ade4de96f1e7a17a0a0199f5287ab803a9c981582b7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "https://twitter.com/jsmesa"
        description = "Dendroid RAT"
        category = "INFO"
        reference = "https://koodous.com/"

    strings:
        $s1 = "/upload-pictures.php?"
        $s2 = "Opened Dialog:"
        $s3 = "com/connect/MyService"
        $s4 = "android/os/Binder"
        $s5 = "android/app/Service"
       condition:
        all of them

}

rule Dendroid_2
{
    meta:
        id = "4Cqpk2spgBELZWNbwJ0dHf"
        fingerprint = "v1_sha256_d131193f66d49ae13751f438153dde5b1824461977983d8b7c63af7117811258"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "https://twitter.com/jsmesa"
        description = "Dendroid evidences via Droidian service"
        category = "INFO"
        reference = "https://koodous.com/"

    strings:
        $a = "Droidian"
        $b = "DroidianService"
       condition:
        all of them

}

rule Dendroid_3
{
    meta:
        id = "38iq3kU1kZLGKaCYzUMA1b"
        fingerprint = "v1_sha256_6db3d45d71e19c6f03b155d862c88ef7c9c46507dc99f2f66a11fb55c95e3616"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "https://twitter.com/jsmesa"
        description = "Dendroid evidences via ServiceReceiver"
        category = "INFO"
        reference = "https://koodous.com/"

    strings:
        $1 = "ServiceReceiver"
        $2 = "Dendroid"
       condition:
        all of them

}
