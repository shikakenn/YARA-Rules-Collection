rule Linux_Rootkit_Diamorphine_716c7ffa {
    meta:
        id = "65n7xtOjlzetNFuKdox56U"
        fingerprint = "v1_sha256_29ae87a563085ff0e4821a994ede16fa3f6fec693418c2e92ac90b839fcfa7cf"
        version = "1.0"
        date = "2024-11-13"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Diamorphine"
        reference_sample = "01fb490fbe2c2b5368cc227abd97e011e83b5e99bb80945ef599fc80e85f8545"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "author=m0nad"
        $str2 = "description=LKM rootkit"
        $str3 = "name=diamorphine"
        $license1 = "license=Dual BSD/GPL"
        $license2 = "license=GPL"
    condition:
        2 of ($str*) and 1 of ($license*)
}

rule Linux_Rootkit_Diamorphine_66eb93c7 {
    meta:
        id = "3bcT4annJDflg8qpO4zPQO"
        fingerprint = "v1_sha256_26063aacb585825f5d6b56d0d671e94efb273605175f4164d271c8edfdbc150a"
        version = "1.0"
        date = "2024-11-13"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Diamorphine"
        reference_sample = "01fb490fbe2c2b5368cc227abd97e011e83b5e99bb80945ef599fc80e85f8545"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $rk1 = "sys_call_table"
        $rk2 = "kallsyms_lookup_name"
        $rk3 = "retpoline=Y"
        $func1 = "get_syscall_table_bf"
        $func2 = "is_invisible"
        $func3 = "hacked_getdents64"
        $func4 = "orig_getdents64"
        $func5 = "give_root"
        $func6 = "module_show"
        $func7 = "module_hide"
        $func8 = "hacked_kill"
        $func9 = "write_cr0_forced"
    condition:
        1 of ($rk*) and 3 of ($func*)
}

