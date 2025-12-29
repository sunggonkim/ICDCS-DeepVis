rule BasicMalware {
    meta:
        description = "Basic keywords for malware benchmark"
    strings:
        $a = "rootkit" nocase
        $b = "hack" nocase
        $c = "exploit" nocase
        $d = "/dev/mem"
        $e = "sys_call_table"
    condition:
        any of them
}

rule ELF_Suspicious {
    meta:
        description = "Suspicious ELF headers"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0 and filesize < 5MB
}
