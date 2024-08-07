rule win_electricfish_auto {

    meta:
        atk_type = "win.electricfish."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.electricfish."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.electricfish"
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
        $sequence_0 = { e8???????? 83c404 85c0 0f84e3fdffff 8b442410 6a00 50 }
            // n = 7, score = 1200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   0f84e3fdffff         | je                  0xfffffde9
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_1 = { e8???????? 8bd8 83c404 85db 7523 683e010000 68???????? }
            // n = 7, score = 1200
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c404               | add                 esp, 4
            //   85db                 | test                ebx, ebx
            //   7523                 | jne                 0x25
            //   683e010000           | push                0x13e
            //   68????????           |                     

        $sequence_2 = { c3 8b5104 57 6a77 68???????? 8910 8b39 }
            // n = 7, score = 1200
            //   c3                   | ret                 
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   57                   | push                edi
            //   6a77                 | push                0x77
            //   68????????           |                     
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b39                 | mov                 edi, dword ptr [ecx]

        $sequence_3 = { 8b442408 6855090000 68???????? 6a41 6896010000 6a14 c70050000000 }
            // n = 7, score = 1200
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   6855090000           | push                0x955
            //   68????????           |                     
            //   6a41                 | push                0x41
            //   6896010000           | push                0x196
            //   6a14                 | push                0x14
            //   c70050000000         | mov                 dword ptr [eax], 0x50

        $sequence_4 = { e8???????? 83c418 85c0 0f8fd7faffff 5f 5e 5d }
            // n = 7, score = 1200
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   85c0                 | test                eax, eax
            //   0f8fd7faffff         | jg                  0xfffffadd
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_5 = { 8945c4 8945c8 8945cc 8945d0 89a540ffffff 6aff 894110 }
            // n = 7, score = 1200
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   89a540ffffff         | mov                 dword ptr [ebp - 0xc0], esp
            //   6aff                 | push                -1
            //   894110               | mov                 dword ptr [ecx + 0x10], eax

        $sequence_6 = { 689b010000 68???????? 6a08 e8???????? 83c40c 85c0 751f }
            // n = 7, score = 1200
            //   689b010000           | push                0x19b
            //   68????????           |                     
            //   6a08                 | push                8
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   751f                 | jne                 0x21

        $sequence_7 = { 51 55 e8???????? 83c408 3bc3 7504 6a6e }
            // n = 7, score = 1200
            //   51                   | push                ecx
            //   55                   | push                ebp
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   3bc3                 | cmp                 eax, ebx
            //   7504                 | jne                 6
            //   6a6e                 | push                0x6e

        $sequence_8 = { c3 57 56 e8???????? 83c408 6893000000 68???????? }
            // n = 7, score = 1200
            //   c3                   | ret                 
            //   57                   | push                edi
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6893000000           | push                0x93
            //   68????????           |                     

        $sequence_9 = { 0fb74550 c7459418001800 c7459848000000 84db 7402 03c0 0fb74d18 }
            // n = 7, score = 1200
            //   0fb74550             | movzx               eax, word ptr [ebp + 0x50]
            //   c7459418001800       | mov                 dword ptr [ebp - 0x6c], 0x180018
            //   c7459848000000       | mov                 dword ptr [ebp - 0x68], 0x48
            //   84db                 | test                bl, bl
            //   7402                 | je                  4
            //   03c0                 | add                 eax, eax
            //   0fb74d18             | movzx               ecx, word ptr [ebp + 0x18]

    condition:
        7 of them and filesize < 3162112
}