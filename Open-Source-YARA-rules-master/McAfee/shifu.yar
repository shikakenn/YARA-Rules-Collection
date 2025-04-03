rule Shifu : Shifu
{
    meta:
        id = "4BGzQMAAEsMvxlapUbsJZf"
        fingerprint = "v1_sha256_dfa6165f8d2750330c71dedbde293780d2bb27e8eb3635e47ca770ff7b9a9d63"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee"
        description = "NA"
        category = "INFO"
        reference = "https://securingtomorrow.mcafee.com/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools/"

strings:

$a = "CryptCreateHash"
$b = "RegCreateKeyA"
$c = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 25 00 73 00 00 00 00 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 00 00 72 00 75 00 6E}
$d = {53 00 6E 00 64 00 56 00 6F 00 6C 00 2E 00 65 00 78 00 65}
$e = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45}

condition:
all of them
}
