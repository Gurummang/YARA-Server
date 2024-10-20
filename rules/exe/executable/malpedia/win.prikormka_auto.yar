rule win_prikormka_auto {

    meta:
        atk_type = "win.prikormka."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.prikormka."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prikormka"
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
        $sequence_0 = { 8d0446 50 e8???????? 83c40c 6a00 56 }
            // n = 6, score = 1600
            //   8d0446               | lea                 eax, [esi + eax*2]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_1 = { 8d1446 52 e8???????? 83c40c }
            // n = 4, score = 1400
            //   8d1446               | lea                 edx, [esi + eax*2]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_2 = { ffd3 8b2d???????? 85c0 7405 }
            // n = 4, score = 1400
            //   ffd3                 | call                ebx
            //   8b2d????????         |                     
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7

        $sequence_3 = { 51 e8???????? 83c40c 68???????? ffd7 }
            // n = 5, score = 1400
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd7                 | call                edi

        $sequence_4 = { 85f6 7420 68???????? ffd7 }
            // n = 4, score = 1400
            //   85f6                 | test                esi, esi
            //   7420                 | je                  0x22
            //   68????????           |                     
            //   ffd7                 | call                edi

        $sequence_5 = { ff15???????? 68???????? ffd7 03c0 50 }
            // n = 5, score = 1400
            //   ff15????????         |                     
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   03c0                 | add                 eax, eax
            //   50                   | push                eax

        $sequence_6 = { 8b1d???????? 83c40c 6a00 56 ffd3 8b2d???????? }
            // n = 6, score = 1400
            //   8b1d????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   8b2d????????         |                     

        $sequence_7 = { 56 ffd3 85c0 7405 6a02 56 }
            // n = 6, score = 1400
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   6a02                 | push                2
            //   56                   | push                esi

        $sequence_8 = { 740e 68???????? 50 ff15???????? ffd0 }
            // n = 5, score = 1400
            //   740e                 | je                  0x10
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   ffd0                 | call                eax

        $sequence_9 = { 68???????? 6a00 6a00 ff15???????? 85c0 7502 59 }
            // n = 7, score = 1000
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4
            //   59                   | pop                 ecx

        $sequence_10 = { 83c40c 8d442404 50 ff15???????? 5e }
            // n = 5, score = 1000
            //   83c40c               | add                 esp, 0xc
            //   8d442404             | lea                 eax, [esp + 4]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5e                   | pop                 esi

        $sequence_11 = { 7408 41 42 3bce }
            // n = 4, score = 1000
            //   7408                 | je                  0xa
            //   41                   | inc                 ecx
            //   42                   | inc                 edx
            //   3bce                 | cmp                 ecx, esi

        $sequence_12 = { 85c0 7502 59 c3 50 ff15???????? b801000000 }
            // n = 7, score = 1000
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   50                   | push                eax
            //   ff15????????         |                     
            //   b801000000           | mov                 eax, 1

        $sequence_13 = { c3 57 6a00 6a00 6a00 6a02 }
            // n = 6, score = 900
            //   c3                   | ret                 
            //   57                   | push                edi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2

        $sequence_14 = { 68???????? ff15???????? 0fb7c0 6683f805 }
            // n = 4, score = 900
            //   68????????           |                     
            //   ff15????????         |                     
            //   0fb7c0               | movzx               eax, ax
            //   6683f805             | cmp                 ax, 5

        $sequence_15 = { ff15???????? ffd0 c705????????01000000 c705????????01000000 }
            // n = 4, score = 900
            //   ff15????????         |                     
            //   ffd0                 | call                eax
            //   c705????????01000000     |     
            //   c705????????01000000     |     

        $sequence_16 = { 5e 85c0 7422 68???????? 50 }
            // n = 5, score = 900
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_17 = { 0fb7c0 6683f805 7d09 b801000000 }
            // n = 4, score = 900
            //   0fb7c0               | movzx               eax, ax
            //   6683f805             | cmp                 ax, 5
            //   7d09                 | jge                 0xb
            //   b801000000           | mov                 eax, 1

        $sequence_18 = { 5e 85c0 7414 c705????????01000000 }
            // n = 4, score = 700
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   c705????????01000000     |     

        $sequence_19 = { 33f6 e8???????? e8???????? e8???????? e8???????? e8???????? e8???????? }
            // n = 7, score = 700
            //   33f6                 | xor                 esi, esi
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_20 = { 50 e8???????? 8b2d???????? 83c40c 6a00 }
            // n = 5, score = 600
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b2d????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0

        $sequence_21 = { ff15???????? 8bf0 ff15???????? 3db7000000 751f 56 }
            // n = 6, score = 600
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   3db7000000           | cmp                 eax, 0xb7
            //   751f                 | jne                 0x21
            //   56                   | push                esi

        $sequence_22 = { 83c102 6685d2 75f5 2bce 8d1400 52 d1f9 }
            // n = 7, score = 600
            //   83c102               | add                 ecx, 2
            //   6685d2               | test                dx, dx
            //   75f5                 | jne                 0xfffffff7
            //   2bce                 | sub                 ecx, esi
            //   8d1400               | lea                 edx, [eax + eax]
            //   52                   | push                edx
            //   d1f9                 | sar                 ecx, 1

        $sequence_23 = { 75f5 8b0d???????? 2bc2 8b15???????? d1f8 }
            // n = 5, score = 600
            //   75f5                 | jne                 0xfffffff7
            //   8b0d????????         |                     
            //   2bc2                 | sub                 eax, edx
            //   8b15????????         |                     
            //   d1f8                 | sar                 eax, 1

        $sequence_24 = { 751f 56 ff15???????? 33c0 }
            // n = 4, score = 600
            //   751f                 | jne                 0x21
            //   56                   | push                esi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_25 = { 6685c9 75f5 2bc6 8d0c12 }
            // n = 4, score = 500
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   2bc6                 | sub                 eax, esi
            //   8d0c12               | lea                 ecx, [edx + edx]

        $sequence_26 = { 2bc6 8d0c12 51 d1f8 }
            // n = 4, score = 500
            //   2bc6                 | sub                 eax, esi
            //   8d0c12               | lea                 ecx, [edx + edx]
            //   51                   | push                ecx
            //   d1f8                 | sar                 eax, 1

        $sequence_27 = { 8b35???????? 83c40c 68???????? ffd6 03c0 }
            // n = 5, score = 500
            //   8b35????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   03c0                 | add                 eax, eax

        $sequence_28 = { 50 e8???????? b8???????? 83c40c 8d5002 }
            // n = 5, score = 500
            //   50                   | push                eax
            //   e8????????           |                     
            //   b8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d5002               | lea                 edx, [eax + 2]

        $sequence_29 = { 75f5 8d0c12 2bc6 51 d1f8 8d544408 }
            // n = 6, score = 500
            //   75f5                 | jne                 0xfffffff7
            //   8d0c12               | lea                 ecx, [edx + edx]
            //   2bc6                 | sub                 eax, esi
            //   51                   | push                ecx
            //   d1f8                 | sar                 eax, 1
            //   8d544408             | lea                 edx, [esp + eax*2 + 8]

        $sequence_30 = { d1f8 8d7102 8da42400000000 668b11 83c102 }
            // n = 5, score = 500
            //   d1f8                 | sar                 eax, 1
            //   8d7102               | lea                 esi, [ecx + 2]
            //   8da42400000000       | lea                 esp, [esp]
            //   668b11               | mov                 dx, word ptr [ecx]
            //   83c102               | add                 ecx, 2

        $sequence_31 = { 85c0 7409 6a02 68???????? }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   6a02                 | push                2
            //   68????????           |                     

        $sequence_32 = { 50 ff15???????? 0fb74c2416 0fb7542414 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   0fb74c2416           | movzx               ecx, word ptr [esp + 0x16]
            //   0fb7542414           | movzx               edx, word ptr [esp + 0x14]

        $sequence_33 = { d1f8 8bd0 b8???????? 8d7002 8da42400000000 668b08 83c002 }
            // n = 7, score = 300
            //   d1f8                 | sar                 eax, 1
            //   8bd0                 | mov                 edx, eax
            //   b8????????           |                     
            //   8d7002               | lea                 esi, [eax + 2]
            //   8da42400000000       | lea                 esp, [esp]
            //   668b08               | mov                 cx, word ptr [eax]
            //   83c002               | add                 eax, 2

        $sequence_34 = { 6685c9 75f5 2bc2 b9???????? d1f8 8d7102 668b11 }
            // n = 7, score = 300
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   2bc2                 | sub                 eax, edx
            //   b9????????           |                     
            //   d1f8                 | sar                 eax, 1
            //   8d7102               | lea                 esi, [ecx + 2]
            //   668b11               | mov                 dx, word ptr [ecx]

        $sequence_35 = { ffd6 50 68???????? 57 ffd6 03c7 50 }
            // n = 7, score = 300
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   68????????           |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax

        $sequence_36 = { 56 57 68???????? 33ff 57 57 ff15???????? }
            // n = 7, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_37 = { e8???????? 83c40c eb0d 6a00 6800020000 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb0d                 | jmp                 0xf
            //   6a00                 | push                0
            //   6800020000           | push                0x200

        $sequence_38 = { d1f8 8d7102 668b11 83c102 6685d2 75f5 8d1400 }
            // n = 7, score = 300
            //   d1f8                 | sar                 eax, 1
            //   8d7102               | lea                 esi, [ecx + 2]
            //   668b11               | mov                 dx, word ptr [ecx]
            //   83c102               | add                 ecx, 2
            //   6685d2               | test                dx, dx
            //   75f5                 | jne                 0xfffffff7
            //   8d1400               | lea                 edx, [eax + eax]

        $sequence_39 = { 6685d2 75f5 8d1400 2bce 52 d1f9 }
            // n = 6, score = 300
            //   6685d2               | test                dx, dx
            //   75f5                 | jne                 0xfffffff7
            //   8d1400               | lea                 edx, [eax + eax]
            //   2bce                 | sub                 ecx, esi
            //   52                   | push                edx
            //   d1f9                 | sar                 ecx, 1

        $sequence_40 = { 6a00 6800020000 ff15???????? 68???????? }
            // n = 4, score = 300
            //   6a00                 | push                0
            //   6800020000           | push                0x200
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_41 = { e8???????? 83c40c 6a00 68???????? ffd3 85c0 7409 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   68????????           |                     
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb

        $sequence_42 = { 6a5c 99 5f f7ff 83f801 }
            // n = 5, score = 100
            //   6a5c                 | push                0x5c
            //   99                   | cdq                 
            //   5f                   | pop                 edi
            //   f7ff                 | idiv                edi
            //   83f801               | cmp                 eax, 1

        $sequence_43 = { 0f87f5090000 ff248505eb0010 33c0 838df4fbffffff 8985a0fbffff }
            // n = 5, score = 100
            //   0f87f5090000         | ja                  0x9fb
            //   ff248505eb0010       | jmp                 dword ptr [eax*4 + 0x1000eb05]
            //   33c0                 | xor                 eax, eax
            //   838df4fbffffff       | or                  dword ptr [ebp - 0x40c], 0xffffffff
            //   8985a0fbffff         | mov                 dword ptr [ebp - 0x460], eax

        $sequence_44 = { 48 48 8975f4 7479 83e848 745f }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   48                   | dec                 eax
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   7479                 | je                  0x7b
            //   83e848               | sub                 eax, 0x48
            //   745f                 | je                  0x61

        $sequence_45 = { 56 8bc3 2bc1 6a5c 99 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   8bc3                 | mov                 eax, ebx
            //   2bc1                 | sub                 eax, ecx
            //   6a5c                 | push                0x5c
            //   99                   | cdq                 

        $sequence_46 = { 32a832d232e0 32e6 3209 3310 3329 333d???????? 335f33 }
            // n = 7, score = 100
            //   32a832d232e0         | xor                 ch, byte ptr [eax - 0x1fcd2dce]
            //   32e6                 | xor                 ah, dh
            //   3209                 | xor                 cl, byte ptr [ecx]
            //   3310                 | xor                 edx, dword ptr [eax]
            //   3329                 | xor                 ebp, dword ptr [ecx]
            //   333d????????         |                     
            //   335f33               | xor                 ebx, dword ptr [edi + 0x33]

    condition:
        7 of them and filesize < 401408
}