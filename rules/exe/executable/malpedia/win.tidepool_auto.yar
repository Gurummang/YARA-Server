rule win_tidepool_auto {

    meta:
        atk_type = "win.tidepool."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.tidepool."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tidepool"
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
        $sequence_0 = { 6a00 50 8b08 ff91a4000000 }
            // n = 4, score = 1000
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff91a4000000         | call                dword ptr [ecx + 0xa4]

        $sequence_1 = { 8b4df4 64890d00000000 59 5f 5e 5b 8b8d00030000 }
            // n = 7, score = 1000
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8b8d00030000         | mov                 ecx, dword ptr [ebp + 0x300]

        $sequence_2 = { 8b8d00030000 33cd e8???????? 81c504030000 }
            // n = 4, score = 1000
            //   8b8d00030000         | mov                 ecx, dword ptr [ebp + 0x300]
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     
            //   81c504030000         | add                 ebp, 0x304

        $sequence_3 = { 83c404 8bc6 5e c20400 80790800 }
            // n = 5, score = 1000
            //   83c404               | add                 esp, 4
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   80790800             | cmp                 byte ptr [ecx + 8], 0

        $sequence_4 = { 53 6a02 8bf1 e8???????? }
            // n = 4, score = 900
            //   53                   | push                ebx
            //   6a02                 | push                2
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     

        $sequence_5 = { 6800000040 8d4500 50 ff15???????? }
            // n = 4, score = 900
            //   6800000040           | push                0x40000000
            //   8d4500               | lea                 eax, [ebp]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { 2bc8 83e906 51 83c006 50 }
            // n = 5, score = 900
            //   2bc8                 | sub                 ecx, eax
            //   83e906               | sub                 ecx, 6
            //   51                   | push                ecx
            //   83c006               | add                 eax, 6
            //   50                   | push                eax

        $sequence_7 = { e8???????? 83c40c 803d????????37 7518 68???????? }
            // n = 5, score = 900
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   803d????????37       |                     
            //   7518                 | jne                 0x1a
            //   68????????           |                     

        $sequence_8 = { 8b4654 8d9698000000 52 8d5678 8b08 }
            // n = 5, score = 800
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]
            //   8d9698000000         | lea                 edx, [esi + 0x98]
            //   52                   | push                edx
            //   8d5678               | lea                 edx, [esi + 0x78]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_9 = { 52 50 8b08 ff91f8000000 85c0 }
            // n = 5, score = 800
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff91f8000000         | call                dword ptr [ecx + 0xf8]
            //   85c0                 | test                eax, eax

        $sequence_10 = { 8b4654 50 8b08 ff5138 }
            // n = 4, score = 800
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5138               | call                dword ptr [ecx + 0x38]

        $sequence_11 = { 8d5658 52 50 ff91d0000000 33ff }
            // n = 5, score = 800
            //   8d5658               | lea                 edx, [esi + 0x58]
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff91d0000000         | call                dword ptr [ecx + 0xd0]
            //   33ff                 | xor                 edi, edi

        $sequence_12 = { c3 56 8bf1 e8???????? 8b4654 }
            // n = 5, score = 800
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]

        $sequence_13 = { 8d45ec 50 681f000200 53 }
            // n = 4, score = 800
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   681f000200           | push                0x2001f
            //   53                   | push                ebx

        $sequence_14 = { 6810270000 ff15???????? 8b45ec 8b08 }
            // n = 4, score = 800
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_15 = { 681f000200 56 68???????? 6801000080 }
            // n = 4, score = 800
            //   681f000200           | push                0x2001f
            //   56                   | push                esi
            //   68????????           |                     
            //   6801000080           | push                0x80000001

        $sequence_16 = { 75f9 b8???????? b900000400 c60000 40 49 }
            // n = 6, score = 800
            //   75f9                 | jne                 0xfffffffb
            //   b8????????           |                     
            //   b900000400           | mov                 ecx, 0x40000
            //   c60000               | mov                 byte ptr [eax], 0
            //   40                   | inc                 eax
            //   49                   | dec                 ecx

        $sequence_17 = { e8???????? 68???????? 68???????? 68???????? 8d4500 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   8d4500               | lea                 eax, [ebp]

        $sequence_18 = { 57 50 6802020000 ff15???????? 68???????? ff15???????? }
            // n = 6, score = 800
            //   57                   | push                edi
            //   50                   | push                eax
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_19 = { 8bc6 5e 5b c20400 6a14 68???????? }
            // n = 6, score = 800
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c20400               | ret                 4
            //   6a14                 | push                0x14
            //   68????????           |                     

        $sequence_20 = { 6805400080 e8???????? 8b542424 52 53 }
            // n = 5, score = 600
            //   6805400080           | push                0x80004005
            //   e8????????           |                     
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   52                   | push                edx
            //   53                   | push                ebx

        $sequence_21 = { 33c9 8aea 83c003 83c504 }
            // n = 4, score = 600
            //   33c9                 | xor                 ecx, ecx
            //   8aea                 | mov                 ch, dl
            //   83c003               | add                 eax, 3
            //   83c504               | add                 ebp, 4

        $sequence_22 = { ff75ec ff15???????? 8b35???????? 6a04 }
            // n = 4, score = 400
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   6a04                 | push                4

        $sequence_23 = { 83651400 8b07 83c40c 837d0c00 0f8ed1000000 8b4d08 41 }
            // n = 7, score = 200
            //   83651400             | and                 dword ptr [ebp + 0x14], 0
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   83c40c               | add                 esp, 0xc
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   0f8ed1000000         | jle                 0xd7
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   41                   | inc                 ecx

        $sequence_24 = { 8bec 8b4508 56 833c850811011000 }
            // n = 4, score = 200
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   833c850811011000     | cmp                 dword ptr [eax*4 + 0x10011108], 0

        $sequence_25 = { 50 ff7508 ff15???????? 395dfc 53 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx
            //   53                   | push                ebx

        $sequence_26 = { 50 8d4604 50 e8???????? 8d45e0 6a04 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8d4604               | lea                 eax, [esi + 4]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   6a04                 | push                4

        $sequence_27 = { 50 89450c ff15???????? 53 ff75fc ff75f8 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_28 = { 8365ec00 8945f4 8d3dd8e30010 8b45f4 d1e0 03f8 }
            // n = 6, score = 200
            //   8365ec00             | and                 dword ptr [ebp - 0x14], 0
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8d3dd8e30010         | lea                 edi, [0x1000e3d8]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   d1e0                 | shl                 eax, 1
            //   03f8                 | add                 edi, eax

    condition:
        7 of them and filesize < 1998848
}