rule win_spectre_auto {

    meta:
        atk_type = "win.spectre."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.spectre."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spectre"
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
        $sequence_0 = { ebe3 83c8ff 5d 5b 59 59 c3 }
            // n = 7, score = 100
            //   ebe3                 | jmp                 0xffffffe5
            //   83c8ff               | or                  eax, 0xffffffff
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   c3                   | ret                 

        $sequence_1 = { 68???????? ff5604 e9???????? 807c242000 0f8414010000 6a02 }
            // n = 6, score = 100
            //   68????????           |                     
            //   ff5604               | call                dword ptr [esi + 4]
            //   e9????????           |                     
            //   807c242000           | cmp                 byte ptr [esp + 0x20], 0
            //   0f8414010000         | je                  0x11a
            //   6a02                 | push                2

        $sequence_2 = { 51 e8???????? 59 59 8b8424ec000000 895c2470 896c2474 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8b8424ec000000       | mov                 eax, dword ptr [esp + 0xec]
            //   895c2470             | mov                 dword ptr [esp + 0x70], ebx
            //   896c2474             | mov                 dword ptr [esp + 0x74], ebp

        $sequence_3 = { 50 e8???????? 83c40c 50 8d8424a0000000 50 e8???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   8d8424a0000000       | lea                 eax, [esp + 0xa0]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 83e801 7440 83e801 742c 83e801 7418 }
            // n = 6, score = 100
            //   83e801               | sub                 eax, 1
            //   7440                 | je                  0x42
            //   83e801               | sub                 eax, 1
            //   742c                 | je                  0x2e
            //   83e801               | sub                 eax, 1
            //   7418                 | je                  0x1a

        $sequence_5 = { 894554 53 8d4dc3 e8???????? 8bc8 e8???????? 50 }
            // n = 7, score = 100
            //   894554               | mov                 dword ptr [ebp + 0x54], eax
            //   53                   | push                ebx
            //   8d4dc3               | lea                 ecx, [ebp - 0x3d]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 83f81b 0f8ee3020000 83f81f 0f8eb3020000 83f821 0f8e06020000 83f822 }
            // n = 7, score = 100
            //   83f81b               | cmp                 eax, 0x1b
            //   0f8ee3020000         | jle                 0x2e9
            //   83f81f               | cmp                 eax, 0x1f
            //   0f8eb3020000         | jle                 0x2b9
            //   83f821               | cmp                 eax, 0x21
            //   0f8e06020000         | jle                 0x20c
            //   83f822               | cmp                 eax, 0x22

        $sequence_7 = { 8b4704 8bcd c6400c01 8b4704 8b4004 c6400c00 8b4704 }
            // n = 7, score = 100
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   8bcd                 | mov                 ecx, ebp
            //   c6400c01             | mov                 byte ptr [eax + 0xc], 1
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   c6400c00             | mov                 byte ptr [eax + 0xc], 0
            //   8b4704               | mov                 eax, dword ptr [edi + 4]

        $sequence_8 = { 51 8d8c2440010000 e8???????? 8d8c24d8000000 e8???????? 8d4c2448 e8???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8d8c2440010000       | lea                 ecx, [esp + 0x140]
            //   e8????????           |                     
            //   8d8c24d8000000       | lea                 ecx, [esp + 0xd8]
            //   e8????????           |                     
            //   8d4c2448             | lea                 ecx, [esp + 0x48]
            //   e8????????           |                     

        $sequence_9 = { c68424c400000000 ff15???????? 59 59 85c0 743d 6a01 }
            // n = 7, score = 100
            //   c68424c400000000     | mov                 byte ptr [esp + 0xc4], 0
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   743d                 | je                  0x3f
            //   6a01                 | push                1

    condition:
        7 of them and filesize < 990208
}