rule win_moonwind_auto {

    meta:
        atk_type = "win.moonwind."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.moonwind."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moonwind"
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
        $sequence_0 = { 8b11 83c104 c1ea08 881430 8a51fc 40 881430 }
            // n = 7, score = 100
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   83c104               | add                 ecx, 4
            //   c1ea08               | shr                 edx, 8
            //   881430               | mov                 byte ptr [eax + esi], dl
            //   8a51fc               | mov                 dl, byte ptr [ecx - 4]
            //   40                   | inc                 eax
            //   881430               | mov                 byte ptr [eax + esi], dl

        $sequence_1 = { 8b5dfc 895de4 8b5de4 66c7030200 8b5dfc 83c308 895de4 }
            // n = 7, score = 100
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   8b5de4               | mov                 ebx, dword ptr [ebp - 0x1c]
            //   66c7030200           | mov                 word ptr [ebx], 2
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   83c308               | add                 ebx, 8
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx

        $sequence_2 = { 53 e8???????? 83c404 8b5d08 8b1b 81c390000000 895dec }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   81c390000000         | add                 ebx, 0x90
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx

        $sequence_3 = { e8???????? 83c404 83c734 33d2 83c8ff 8917 885704 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83c734               | add                 edi, 0x34
            //   33d2                 | xor                 edx, edx
            //   83c8ff               | or                  eax, 0xffffffff
            //   8917                 | mov                 dword ptr [edi], edx
            //   885704               | mov                 byte ptr [edi + 4], dl

        $sequence_4 = { b801000000 eb05 b800000000 85c0 0f842f000000 8b5d08 8b1b }
            // n = 7, score = 100
            //   b801000000           | mov                 eax, 1
            //   eb05                 | jmp                 7
            //   b800000000           | mov                 eax, 0
            //   85c0                 | test                eax, eax
            //   0f842f000000         | je                  0x35
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]

        $sequence_5 = { bbdc090000 e8???????? 83c410 8945b8 8b5dbc 85db 7409 }
            // n = 7, score = 100
            //   bbdc090000           | mov                 ebx, 0x9dc
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8945b8               | mov                 dword ptr [ebp - 0x48], eax
            //   8b5dbc               | mov                 ebx, dword ptr [ebp - 0x44]
            //   85db                 | test                ebx, ebx
            //   7409                 | je                  0xb

        $sequence_6 = { ff75fc 6801000000 bb68010000 e8???????? 83c410 8945f0 68???????? }
            // n = 7, score = 100
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   6801000000           | push                1
            //   bb68010000           | mov                 ebx, 0x168
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   68????????           |                     

        $sequence_7 = { 8965f4 8b5d08 ff33 6801000000 ff75f8 ff15???????? }
            // n = 6, score = 100
            //   8965f4               | mov                 dword ptr [ebp - 0xc], esp
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   ff33                 | push                dword ptr [ebx]
            //   6801000000           | push                1
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     

        $sequence_8 = { 50 e8???????? 8d7c2434 83c9ff 33c0 83c40c f2ae }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d7c2434             | lea                 edi, [esp + 0x34]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   83c40c               | add                 esp, 0xc
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_9 = { dc25???????? dd5dc4 6801030080 6a00 682c000000 dd45c4 e8???????? }
            // n = 7, score = 100
            //   dc25????????         |                     
            //   dd5dc4               | fstp                qword ptr [ebp - 0x3c]
            //   6801030080           | push                0x80000301
            //   6a00                 | push                0
            //   682c000000           | push                0x2c
            //   dd45c4               | fld                 qword ptr [ebp - 0x3c]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1417216
}