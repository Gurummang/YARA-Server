rule win_red_gambler_auto {

    meta:
        atk_type = "win.red_gambler."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.red_gambler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.red_gambler"
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
        $sequence_0 = { 807e01a2 7535 807e02c3 752f 68???????? 68???????? ff15???????? }
            // n = 7, score = 400
            //   807e01a2             | cmp                 byte ptr [esi + 1], 0xa2
            //   7535                 | jne                 0x37
            //   807e02c3             | cmp                 byte ptr [esi + 2], 0xc3
            //   752f                 | jne                 0x31
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_1 = { 68???????? c745ece80f13fc ffd6 a3???????? }
            // n = 4, score = 400
            //   68????????           |                     
            //   c745ece80f13fc       | mov                 dword ptr [ebp - 0x14], 0xfc130fe8
            //   ffd6                 | call                esi
            //   a3????????           |                     

        $sequence_2 = { 68ff000000 8d8df0fcffff 51 ff15???????? 85c0 }
            // n = 5, score = 400
            //   68ff000000           | push                0xff
            //   8d8df0fcffff         | lea                 ecx, [ebp - 0x310]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { 3bf1 72bf 5e 33c0 5b }
            // n = 5, score = 400
            //   3bf1                 | cmp                 esi, ecx
            //   72bf                 | jb                  0xffffffc1
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx

        $sequence_4 = { e8???????? 8bf8 83c404 83ffff 74e1 57 8d4c244c }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4
            //   83ffff               | cmp                 edi, -1
            //   74e1                 | je                  0xffffffe3
            //   57                   | push                edi
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]

        $sequence_5 = { 8d4c2414 51 6a40 6a07 }
            // n = 4, score = 400
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   51                   | push                ecx
            //   6a40                 | push                0x40
            //   6a07                 | push                7

        $sequence_6 = { 68???????? 68???????? ffd6 5e 85c0 7505 }
            // n = 6, score = 400
            //   68????????           |                     
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7

        $sequence_7 = { 894dec 8955f0 8945f4 ff15???????? }
            // n = 4, score = 400
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   ff15????????         |                     

        $sequence_8 = { 2b2a bee7eee947 7c26 0e }
            // n = 4, score = 300
            //   2b2a                 | sub                 ebp, dword ptr [edx]
            //   bee7eee947           | mov                 esi, 0x47e9eee7
            //   7c26                 | jl                  0x28
            //   0e                   | push                cs

        $sequence_9 = { 8d4d98 51 ff15???????? 8d5598 52 8d8598fdffff }
            // n = 6, score = 300
            //   8d4d98               | lea                 ecx, [ebp - 0x68]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d5598               | lea                 edx, [ebp - 0x68]
            //   52                   | push                edx
            //   8d8598fdffff         | lea                 eax, [ebp - 0x268]

        $sequence_10 = { 7456 7b78 cd50 d46e }
            // n = 4, score = 300
            //   7456                 | je                  0x58
            //   7b78                 | jnp                 0x7a
            //   cd50                 | int                 0x50
            //   d46e                 | aam                 0x6e

        $sequence_11 = { bc340e65bc 691fd8727fcf 14cf fd }
            // n = 4, score = 300
            //   bc340e65bc           | mov                 esp, 0xbc650e34
            //   691fd8727fcf         | imul                ebx, dword ptr [edi], 0xcf7f72d8
            //   14cf                 | adc                 al, 0xcf
            //   fd                   | std                 

        $sequence_12 = { 9e e779 9e 54 }
            // n = 4, score = 300
            //   9e                   | sahf                
            //   e779                 | out                 0x79, eax
            //   9e                   | sahf                
            //   54                   | push                esp

        $sequence_13 = { 51 ff15???????? 83c414 6a00 6a00 8d9598fbffff }
            // n = 6, score = 300
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d9598fbffff         | lea                 edx, [ebp - 0x468]

        $sequence_14 = { ff15???????? 6800010000 8d8d98fdffff 51 8d9598feffff 52 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   6800010000           | push                0x100
            //   8d8d98fdffff         | lea                 ecx, [ebp - 0x268]
            //   51                   | push                ecx
            //   8d9598feffff         | lea                 edx, [ebp - 0x168]
            //   52                   | push                edx

        $sequence_15 = { 52 8d8598fdffff 50 68???????? }
            // n = 4, score = 300
            //   52                   | push                edx
            //   8d8598fdffff         | lea                 eax, [ebp - 0x268]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_16 = { 3c3d 9e e7bd e600 3e3e25162f062d }
            // n = 5, score = 300
            //   3c3d                 | cmp                 al, 0x3d
            //   9e                   | sahf                
            //   e7bd                 | out                 0xbd, eax
            //   e600                 | out                 0, al
            //   3e3e25162f062d       | and                 eax, 0x2d062f16

        $sequence_17 = { 6a00 6a00 8d9598fbffff 52 68???????? 6a00 6a00 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d9598fbffff         | lea                 edx, [ebp - 0x468]
            //   52                   | push                edx
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_18 = { 50 4c 48 44 40 6c }
            // n = 6, score = 300
            //   50                   | push                eax
            //   4c                   | dec                 esp
            //   48                   | dec                 eax
            //   44                   | inc                 esp
            //   40                   | inc                 eax
            //   6c                   | insb                byte ptr es:[edi], dx

        $sequence_19 = { 6800010000 8d8dfcfdffff 51 6a00 }
            // n = 4, score = 300
            //   6800010000           | push                0x100
            //   8d8dfcfdffff         | lea                 ecx, [ebp - 0x204]
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_20 = { 68???????? 8d8d98fbffff 68???????? 51 ff15???????? 83c414 }
            // n = 6, score = 300
            //   68????????           |                     
            //   8d8d98fbffff         | lea                 ecx, [ebp - 0x468]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14

        $sequence_21 = { 7c0e 07 642827 3ccf }
            // n = 4, score = 300
            //   7c0e                 | jl                  0x10
            //   07                   | pop                 es
            //   642827               | sub                 byte ptr fs:[edi], ah
            //   3ccf                 | cmp                 al, 0xcf

        $sequence_22 = { 8d9598feffff 52 ff15???????? 8d8594fbffff 50 8d4d98 51 }
            // n = 7, score = 300
            //   8d9598feffff         | lea                 edx, [ebp - 0x168]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8d8594fbffff         | lea                 eax, [ebp - 0x46c]
            //   50                   | push                eax
            //   8d4d98               | lea                 ecx, [ebp - 0x68]
            //   51                   | push                ecx

        $sequence_23 = { 6800010000 8d85fcfeffff 50 6a00 ff15???????? }
            // n = 5, score = 300
            //   6800010000           | push                0x100
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_24 = { 2f 74be 6f 665b }
            // n = 4, score = 300
            //   2f                   | das                 
            //   74be                 | je                  0xffffffc0
            //   6f                   | outsd               dx, dword ptr [esi]
            //   665b                 | pop                 bx

        $sequence_25 = { 68???????? ff15???????? 8b7508 c7465c486b4000 83660800 }
            // n = 5, score = 100
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   c7465c486b4000       | mov                 dword ptr [esi + 0x5c], 0x406b48
            //   83660800             | and                 dword ptr [esi + 8], 0

        $sequence_26 = { 6888130000 ffd7 6800010000 8d95fcfeffff }
            // n = 4, score = 100
            //   6888130000           | push                0x1388
            //   ffd7                 | call                edi
            //   6800010000           | push                0x100
            //   8d95fcfeffff         | lea                 edx, [ebp - 0x104]

        $sequence_27 = { 55 8bec 8b4508 ff34c5d0814000 }
            // n = 4, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff34c5d0814000       | push                dword ptr [eax*8 + 0x4081d0]

        $sequence_28 = { 8bf8 ffd3 8bd8 ffd7 8b3d???????? 6aff ffd7 }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   ffd3                 | call                ebx
            //   8bd8                 | mov                 ebx, eax
            //   ffd7                 | call                edi
            //   8b3d????????         |                     
            //   6aff                 | push                -1
            //   ffd7                 | call                edi

        $sequence_29 = { 83f805 7d10 668b4c4310 66890c4580974000 40 ebe8 }
            // n = 6, score = 100
            //   83f805               | cmp                 eax, 5
            //   7d10                 | jge                 0x12
            //   668b4c4310           | mov                 cx, word ptr [ebx + eax*2 + 0x10]
            //   66890c4580974000     | mov                 word ptr [eax*2 + 0x409780], cx
            //   40                   | inc                 eax
            //   ebe8                 | jmp                 0xffffffea

        $sequence_30 = { 6a5c 8d8dfcfeffff 51 ff15???????? }
            // n = 4, score = 100
            //   6a5c                 | push                0x5c
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_31 = { 8bec 8b4508 33c9 3b04cd10804000 }
            // n = 4, score = 100
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   3b04cd10804000       | cmp                 eax, dword ptr [ecx*8 + 0x408010]

    condition:
        7 of them and filesize < 327680
}