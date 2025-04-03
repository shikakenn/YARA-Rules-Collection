import "elf"

rule single_load_rwe
{
    meta:
        id = "2mTSMOGlFoo2HmuiAHk28H"
        fingerprint = "v1_sha256_704b8cbe70b053bbfec911a22e3c4d34214b840facd2987ca46f0512bd320f9d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Flags binaries with a single LOAD segment marked as RWE."
        category = "INFO"
        hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"
        family = "Stager"
        filetype = "ELF"

    condition:
        elf.number_of_segments == 1 and
        elf.segments[0].type == elf.PT_LOAD and
        elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address
{
    meta:
        id = "fEyTc0H0O52ShMlEtbmrD"
        fingerprint = "v1_sha256_19bcfdab5fb8cbe0b059fbddae610b757a275940473901b8ff5a1ae0b3c96131"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "A fake sections header has been added to the binary."
        category = "INFO"
        hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"
        family = "Obfuscation"
        filetype = "ELF"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_segments > 0 and
        elf.number_of_sections > 0 and
        not
        (
            for any i in (0..elf.number_of_segments):
            (
                (elf.segments[i].offset <= elf.entry_point) and
                ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].offset <= elf.entry_point and
                    ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
                    (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
                    (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
                )
            )
        )
}

rule fake_dynamic_symbols
{
    meta:
        id = "1brVganKzxYeCUdi8ejGee"
        fingerprint = "v1_sha256_9c0cd55b42ebc9cea770035f83441c1e8ef955bb72db5cf5b958873e3674070c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "A fake dynamic symbol table has been added to the binary"
        category = "INFO"
        hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"
        family = "Obfuscation"
        filetype = "ELF"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_sections > 0 and
        elf.dynamic_section_entries > 0 and
        for any i in (0..elf.dynamic_section_entries):
        (
            elf.dynamic[i].type == elf.DT_SYMTAB and
            not
            (
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].type == elf.SHT_DYNSYM and
                    for any k in (0..elf.number_of_segments):
                    (
                        (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
                        ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
                        (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
                    )
                )
            )
        )
}
