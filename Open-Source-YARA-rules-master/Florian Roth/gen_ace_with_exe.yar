
rule ACE_Containing_EXE {
    meta:
        id = "jsUYMeaa9ADKw9PYRC1nB"
        fingerprint = "v1_sha256_a4dc39e412b041492602d41f7ce1f7b821e17584a43e5cdc54ffe686742a5f9a"
        version = "1.0"
        score = 50
        date = "2015-09-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth - based on Nick Hoffman' rule - Morphick Inc"
        description = "Looks for ACE Archives containing an exe/scr file"
        category = "INFO"

    strings:
        $header = { 2a 2a 41 43 45 2a 2a }
        $extensions1 = ".exe" 
        $extensions2 = ".EXE"
        $extensions3 = ".scr"
        $extensions4 = ".SCR"
    condition:
        $header at 7 and for
        any of ($extensions*): (
            $ in (81..(81+uint16(79)))
        )
}


