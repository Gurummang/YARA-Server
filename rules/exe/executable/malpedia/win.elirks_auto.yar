rule win_elirks_auto {

    meta:
        atk_type = "win.elirks."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.elirks."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.elirks"
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
        $sequence_0 = { 8d4c2414 51 68???????? 8bf0 ff15???????? }
            // n = 5, score = 100
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   51                   | push                ecx
            //   68????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     

        $sequence_1 = { 85c0 7417 8b44241c 01442414 03f0 2bf8 e9???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7417                 | je                  0x19
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   01442414             | add                 dword ptr [esp + 0x14], eax
            //   03f0                 | add                 esi, eax
            //   2bf8                 | sub                 edi, eax
            //   e9????????           |                     

        $sequence_2 = { 51 8d44241c e8???????? 8b8e04600000 83c404 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   e8????????           |                     
            //   8b8e04600000         | mov                 ecx, dword ptr [esi + 0x6004]
            //   83c404               | add                 esp, 4

        $sequence_3 = { 83c102 66c7012d00 83c102 66c7012d00 83c102 83ef03 83c603 }
            // n = 7, score = 100
            //   83c102               | add                 ecx, 2
            //   66c7012d00           | mov                 word ptr [ecx], 0x2d
            //   83c102               | add                 ecx, 2
            //   66c7012d00           | mov                 word ptr [ecx], 0x2d
            //   83c102               | add                 ecx, 2
            //   83ef03               | sub                 edi, 3
            //   83c603               | add                 esi, 3

        $sequence_4 = { 68???????? 8d442430 e8???????? 83c40c }
            // n = 4, score = 100
            //   68????????           |                     
            //   8d442430             | lea                 eax, [esp + 0x30]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_5 = { 7fe8 85ff 0f84a1010000 85ff 7e25 }
            // n = 5, score = 100
            //   7fe8                 | jg                  0xffffffea
            //   85ff                 | test                edi, edi
            //   0f84a1010000         | je                  0x1a7
            //   85ff                 | test                edi, edi
            //   7e25                 | jle                 0x27

        $sequence_6 = { c1f803 0faf4608 894614 6a68 }
            // n = 4, score = 100
            //   c1f803               | sar                 eax, 3
            //   0faf4608             | imul                eax, dword ptr [esi + 8]
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   6a68                 | push                0x68

        $sequence_7 = { 52 ff15???????? 8bd8 83fbff 895c2410 7546 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   83fbff               | cmp                 ebx, -1
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx
            //   7546                 | jne                 0x48

        $sequence_8 = { 8d8c2490060000 51 6804010000 ff15???????? 8d9e0c600000 53 6a00 }
            // n = 7, score = 100
            //   8d8c2490060000       | lea                 ecx, [esp + 0x690]
            //   51                   | push                ecx
            //   6804010000           | push                0x104
            //   ff15????????         |                     
            //   8d9e0c600000         | lea                 ebx, [esi + 0x600c]
            //   53                   | push                ebx
            //   6a00                 | push                0

        $sequence_9 = { 750b 57 e8???????? 83c404 5e c3 }
            // n = 6, score = 100
            //   750b                 | jne                 0xd
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 81920
}