rule win_buer_auto {

    meta:
        atk_type = "win.buer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.buer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.buer"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8b4014 8b00 8b4010 8945fc 61 8b45fc }
            // n = 6, score = 1100
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   61                   | popal               
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_1 = { 7507 e8???????? eb05 e8???????? 46 83fe20 7cd1 }
            // n = 7, score = 1100
            //   7507                 | jne                 9
            //   e8????????           |                     
            //   eb05                 | jmp                 7
            //   e8????????           |                     
            //   46                   | inc                 esi
            //   83fe20               | cmp                 esi, 0x20
            //   7cd1                 | jl                  0xffffffd3

        $sequence_2 = { 60 64a130000000 8b400c 8b4014 8b00 8b4010 }
            // n = 6, score = 1100
            //   60                   | pushal              
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]

        $sequence_3 = { 8bc2 eb19 33c0 85d2 7e13 3bc7 }
            // n = 6, score = 1100
            //   8bc2                 | mov                 eax, edx
            //   eb19                 | jmp                 0x1b
            //   33c0                 | xor                 eax, eax
            //   85d2                 | test                edx, edx
            //   7e13                 | jle                 0x15
            //   3bc7                 | cmp                 eax, edi

        $sequence_4 = { 8b55e8 015158 8b55d8 894148 8b45dc 03c6 89414c }
            // n = 7, score = 1100
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   015158               | add                 dword ptr [ecx + 0x58], edx
            //   8b55d8               | mov                 edx, dword ptr [ebp - 0x28]
            //   894148               | mov                 dword ptr [ecx + 0x48], eax
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   03c6                 | add                 eax, esi
            //   89414c               | mov                 dword ptr [ecx + 0x4c], eax

        $sequence_5 = { c1e104 0bc8 6a02 5b }
            // n = 4, score = 1100
            //   c1e104               | shl                 ecx, 4
            //   0bc8                 | or                  ecx, eax
            //   6a02                 | push                2
            //   5b                   | pop                 ebx

        $sequence_6 = { 8945f8 ff15???????? 59 59 85c0 }
            // n = 5, score = 1100
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_7 = { 8365fc00 53 56 57 60 64a130000000 8b400c }
            // n = 7, score = 1100
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   60                   | pushal              
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]

        $sequence_8 = { c744240402000000 8d442428 c7442408???????? c744240c01000000 }
            // n = 4, score = 300
            //   c744240402000000     | mov                 dword ptr [esp + 4], 2
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   c7442408????????     |                     
            //   c744240c01000000     | mov                 dword ptr [esp + 0xc], 1

        $sequence_9 = { e8???????? 80fb03 7705 80fb02 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   80fb03               | cmp                 bl, 3
            //   7705                 | ja                  7
            //   80fb02               | cmp                 bl, 2

        $sequence_10 = { e8???????? 0f0b b92c000000 ba01000000 e8???????? 0f0b 89f9 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   0f0b                 | ud2                 
            //   b92c000000           | mov                 ecx, 0x2c
            //   ba01000000           | mov                 edx, 1
            //   e8????????           |                     
            //   0f0b                 | ud2                 
            //   89f9                 | mov                 ecx, edi

        $sequence_11 = { c744240401000000 c7442408???????? c744240c01000000 89442410 }
            // n = 4, score = 300
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   c7442408????????     |                     
            //   c744240c01000000     | mov                 dword ptr [esp + 0xc], 1
            //   89442410             | mov                 dword ptr [esp + 0x10], eax

        $sequence_12 = { e8???????? 56 6a00 50 e8???????? c7471c01000000 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   56                   | push                esi
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   c7471c01000000       | mov                 dword ptr [edi + 0x1c], 1

        $sequence_13 = { c744240800000000 57 e8???????? 85c0 }
            // n = 4, score = 300
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_14 = { cd29 0f0b cc 8b442404 833800 7406 ba???????? }
            // n = 7, score = 300
            //   cd29                 | int                 0x29
            //   0f0b                 | ud2                 
            //   cc                   | int3                
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   833800               | cmp                 dword ptr [eax], 0
            //   7406                 | je                  8
            //   ba????????           |                     

        $sequence_15 = { e8???????? 80fb05 ba01000000 0fb6c3 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   80fb05               | cmp                 bl, 5
            //   ba01000000           | mov                 edx, 1
            //   0fb6c3               | movzx               eax, bl

    condition:
        7 of them and filesize < 3031040
}