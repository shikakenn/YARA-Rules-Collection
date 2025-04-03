rule Ratty
{
    meta:
        id = "5lAxXMsdzhHknTyStNACgs"
        fingerprint = "v1_sha256_fb9c9f14333868396cd263e4b396e9470af3f1e999f0eb8f39c22504e2ad71fa"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "mikesxrs"
        Description = "Looking for unique code"
        Date = "2017-10-28"
        Reference1 = "https://github.com/shotskeber/Ratty/tree/master/Ratty/src/de/sogomn/rat"
        Reference2 = "https://www.first.org/resources/papers/conf2016/FIRST-2016-122.pdf"
        md5 = "6882e9a5973384e096bd41f210cddb54"
        md5 = "5159798395b2e0a91e28a457c935668b"

    strings:
        $STR1 = "RattyClient.class"
        $STR2 = "sogomn/rat/"
        $STR3 = "RattyServer.class"
    condition:
        all of them
}
