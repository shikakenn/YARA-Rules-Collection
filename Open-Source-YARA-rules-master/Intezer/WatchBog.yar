rule WatchBog_Cython
{	
    meta:
        id = "xTGUDpkNNKxy24FHun21q"
        fingerprint = "v1_sha256_db652d786f87d67e7c37239d871ab1d9a3604104f83426603024f0bd219aad11"
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
    $a0 = "/tmp/.parttttzone"
    $a1 = "__pyx_kp_s_watchbog_dev"
    $a2 = "__pyx_k_watchbog_dev"
    $a3 = "__pyx_n_s_watchbog" 
    $a4 = "__pyx_k_watchbog"
    $b0 = "jail.BlueKeep"
    $b1 = "jail.Pwn"
    $b2 = "jail.Crack"
    $b3 = "jail.Solr"
    $b4 = "jail.Jira"
    $b5 = "jail.Couchdb"
    $b6 = "jail.Jenkins"
    $b7 = "jail.Laravel"
    $b8 = "jail.Bot"
    condition:
    any of ($a*) and 2 of ($b*)
}
