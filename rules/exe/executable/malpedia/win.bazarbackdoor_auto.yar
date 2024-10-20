rule win_bazarbackdoor_auto {

    meta:
        atk_type = "win.bazarbackdoor."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.bazarbackdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bazarbackdoor"
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
        $sequence_0 = { 488bce 4889442420 ff15???????? 85c0 780a }
            // n = 5, score = 1500
            //   488bce               | setne               dl
            //   4889442420           | add                 edx, 0x24
            //   ff15????????         |                     
            //   85c0                 | cmp                 ecx, 2
            //   780a                 | setne               dl

        $sequence_1 = { 488bce ffd0 eb03 488bc3 }
            // n = 4, score = 1300
            //   488bce               | push                ebx
            //   ffd0                 | push                ebp
            //   eb03                 | mov                 al, byte ptr [esp + 0x383]
            //   488bc3               | cmp                 esi, 0x80

        $sequence_2 = { b803000000 e9???????? 488b5568 4c8d85f0040000 488b4c2450 bb08000000 }
            // n = 6, score = 1300
            //   b803000000           | lea                 edx, [ebp + eax + 0x79f]
            //   e9????????           |                     
            //   488b5568             | dec                 eax
            //   4c8d85f0040000       | mov                 dword ptr [esp + 0x28], eax
            //   488b4c2450           | dec                 eax
            //   bb08000000           | lea                 edx, [ebp + 0x7a0]

        $sequence_3 = { e9???????? 488b4c2458 488d55e0 ff15???????? }
            // n = 4, score = 1300
            //   e9????????           |                     
            //   488b4c2458           | dec                 eax
            //   488d55e0             | lea                 eax, [esp + 0x70]
            //   ff15????????         |                     

        $sequence_4 = { 4533c0 c744242002000000 ba00000040 ffd0 }
            // n = 4, score = 1100
            //   4533c0               | js                  0x1c
            //   c744242002000000     | dec                 eax
            //   ba00000040           | mov                 ecx, esi
            //   ffd0                 | dec                 eax

        $sequence_5 = { 0fb70f ff15???????? 0fb74f02 0fb7d8 ff15???????? }
            // n = 5, score = 1100
            //   0fb70f               | movzx               ecx, word ptr [edi]
            //   ff15????????         |                     
            //   0fb74f02             | movzx               ecx, word ptr [edi + 2]
            //   0fb7d8               | movzx               ebx, ax
            //   ff15????????         |                     

        $sequence_6 = { 488d4d80 e8???????? 498bd6 488d4d80 }
            // n = 4, score = 1100
            //   488d4d80             | inc                 ecx
            //   e8????????           |                     
            //   498bd6               | mov                 eax, 0x100f
            //   488d4d80             | dec                 eax

        $sequence_7 = { 7507 33c0 e9???????? b8ff000000 }
            // n = 4, score = 1000
            //   7507                 | test                dl, dl
            //   33c0                 | je                  7
            //   e9????????           |                     
            //   b8ff000000           | cmp                 dl, 0x2e

        $sequence_8 = { 0fb7d8 ff15???????? 0fb74f08 440fb7e8 }
            // n = 4, score = 1000
            //   0fb7d8               | movzx               ebx, ax
            //   ff15????????         |                     
            //   0fb74f08             | movzx               ecx, word ptr [edi + 8]
            //   440fb7e8             | inc                 esp

        $sequence_9 = { 4885c9 7406 488b11 ff5210 ff15???????? }
            // n = 5, score = 900
            //   4885c9               | movzx               ecx, word ptr [edi + 2]
            //   7406                 | movzx               ebx, ax
            //   488b11               | movzx               ecx, word ptr [edi + 8]
            //   ff5210               | inc                 esp
            //   ff15????????         |                     

        $sequence_10 = { e8???????? cc e8???????? cc 4053 4883ec20 b902000000 }
            // n = 7, score = 900
            //   e8????????           |                     
            //   cc                   | je                  7
            //   e8????????           |                     
            //   cc                   | cmp                 dl, 0x2e
            //   4053                 | jne                 0x14
            //   4883ec20             | movzx               eax, cl
            //   b902000000           | test                dl, dl

        $sequence_11 = { c3 0fb74c0818 b80b010000 663bc8 }
            // n = 4, score = 900
            //   c3                   | dec                 eax
            //   0fb74c0818           | mov                 edx, ebx
            //   b80b010000           | dec                 esp
            //   663bc8               | mov                 eax, ebx

        $sequence_12 = { e8???????? 4c89e1 e8???????? 8b05???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4c89e1               | test                eax, eax
            //   e8????????           |                     
            //   8b05????????         |                     

        $sequence_13 = { 4533c9 4889442428 488d95a0070000 488d442470 41b80f100000 }
            // n = 5, score = 800
            //   4533c9               | mov                 eax, 0x100f
            //   4889442428           | dec                 eax
            //   488d95a0070000       | mov                 ecx, esi
            //   488d442470           | dec                 eax
            //   41b80f100000         | mov                 dword ptr [esp + 0x20], eax

        $sequence_14 = { 0fb6c9 4881e9c0000000 48c1e108 4803c8 8bc1 488d94059f070000 }
            // n = 6, score = 800
            //   0fb6c9               | mov                 ecx, esi
            //   4881e9c0000000       | dec                 eax
            //   48c1e108             | mov                 dword ptr [esp + 0x20], eax
            //   4803c8               | test                eax, eax
            //   8bc1                 | js                  0x1c
            //   488d94059f070000     | dec                 eax

        $sequence_15 = { 31ff 4889c1 31d2 4989f0 }
            // n = 4, score = 800
            //   31ff                 | mov                 dword ptr [esp + 8], ecx
            //   4889c1               | dec                 eax
            //   31d2                 | sub                 esp, 0x48
            //   4989f0               | mov                 eax, dword ptr [esp + 0x58]

        $sequence_16 = { 4889f1 e8???????? 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   4889f1               | cwde                
            //   e8????????           |                     
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_17 = { 4c89742440 4c89742438 4489742430 4c89742428 }
            // n = 4, score = 800
            //   4c89742440           | je                  8
            //   4c89742438           | dec                 eax
            //   4489742430           | mov                 edx, dword ptr [ecx]
            //   4c89742428           | call                dword ptr [edx + 0x10]

        $sequence_18 = { ff15???????? 4889c1 31d2 4d89e0 }
            // n = 4, score = 800
            //   ff15????????         |                     
            //   4889c1               | mov                 dword ptr [esp + 0x24], eax
            //   31d2                 | dec                 eax
            //   4d89e0               | mov                 dword ptr [esp + 0x28], 0

        $sequence_19 = { 418d5508 488bc8 ff15???????? 488bd8 }
            // n = 4, score = 800
            //   418d5508             | movzx               ebp, ax
            //   488bc8               | dec                 eax
            //   ff15????????         |                     
            //   488bd8               | test                ecx, ecx

        $sequence_20 = { e8???????? 4889c7 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4889c7               | mov                 dword ptr [esp + 0x20], eax
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_21 = { 488d9590050000 488bce ff15???????? 85c0 }
            // n = 4, score = 800
            //   488d9590050000       | test                eax, eax
            //   488bce               | js                  0x13
            //   ff15????????         |                     
            //   85c0                 | inc                 ecx

        $sequence_22 = { 488d442470 41b80f100000 488bce 4889442420 }
            // n = 4, score = 800
            //   488d442470           | call                esi
            //   41b80f100000         | lea                 esi, [eax + 1]
            //   488bce               | push                esi
            //   4889442420           | push                8

        $sequence_23 = { ff15???????? ff15???????? 4d8bc5 33d2 488bc8 }
            // n = 5, score = 800
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   4d8bc5               | inc                 ecx
            //   33d2                 | lea                 edx, [ebp + 8]
            //   488bc8               | dec                 eax

        $sequence_24 = { 0fafc8 89c8 83f0fe 85c8 0f95c0 0f94c3 }
            // n = 6, score = 700
            //   0fafc8               | dec                 ecx
            //   89c8                 | mov                 eax, ebx
            //   83f0fe               | dec                 eax
            //   85c8                 | mov                 ecx, eax
            //   0f95c0               | xor                 edx, edx
            //   0f94c3               | dec                 ecx

        $sequence_25 = { c744242003000000 4889f9 ba00000080 41b801000000 }
            // n = 4, score = 700
            //   c744242003000000     | inc                 ecx
            //   4889f9               | mov                 eax, 0x100f
            //   ba00000080           | dec                 eax
            //   41b801000000         | mov                 ecx, esi

        $sequence_26 = { c744242800000001 4533c9 4533c0 c744242002000000 ba1f000f00 }
            // n = 5, score = 700
            //   c744242800000001     | mov                 dword ptr [esp + 0x28], 0x80
            //   4533c9               | mov                 dword ptr [esp + 0x20], 3
            //   4533c0               | dec                 eax
            //   c744242002000000     | mov                 ecx, edi
            //   ba1f000f00           | mov                 edx, 0x80000000

        $sequence_27 = { 83fe09 0f9fc2 83fe0a 0f9cc1 }
            // n = 4, score = 700
            //   83fe09               | dec                 eax
            //   0f9fc2               | cwde                
            //   83fe0a               | dec                 eax
            //   0f9cc1               | mov                 dword ptr [esp + 0x20], eax

        $sequence_28 = { 4889442428 488d95b0030000 488d4580 41b80f100000 }
            // n = 4, score = 700
            //   4889442428           | dec                 esp
            //   488d95b0030000       | mov                 dword ptr [esp + 0x38], esi
            //   488d4580             | inc                 esp
            //   41b80f100000         | mov                 dword ptr [esp + 0x30], esi

        $sequence_29 = { 4d8bc7 33d2 488bc8 ff15???????? ff15???????? }
            // n = 5, score = 700
            //   4d8bc7               | xor                 edx, edx
            //   33d2                 | dec                 eax
            //   488bc8               | mov                 ecx, eax
            //   ff15????????         |                     
            //   ff15????????         |                     

        $sequence_30 = { 08ca 80f201 7502 ebfe }
            // n = 4, score = 700
            //   08ca                 | xor                 edx, edx
            //   80f201               | dec                 ecx
            //   7502                 | mov                 eax, ebx
            //   ebfe                 | dec                 eax

        $sequence_31 = { 48c744243000000000 c744242880000000 c744242003000000 4889f9 }
            // n = 4, score = 700
            //   48c744243000000000     | dec    eax
            //   c744242880000000     | mov                 ecx, esi
            //   c744242003000000     | dec                 eax
            //   4889f9               | mov                 dword ptr [esp + 0x20], eax

        $sequence_32 = { 0f94c3 83f809 0f9fc2 83f80a 0f9cc0 30d8 }
            // n = 6, score = 700
            //   0f94c3               | movzx               ebx, ax
            //   83f809               | movzx               ecx, word ptr [edi + 8]
            //   0f9fc2               | inc                 esp
            //   83f80a               | movzx               ebp, ax
            //   0f9cc0               | dec                 ebp
            //   30d8                 | mov                 eax, ebp

        $sequence_33 = { 0fb65305 33c0 80f973 0f94c0 }
            // n = 4, score = 700
            //   0fb65305             | mov                 ecx, esi
            //   33c0                 | dec                 eax
            //   80f973               | mov                 dword ptr [esp + 0x20], eax
            //   0f94c0               | test                eax, eax

        $sequence_34 = { 0f9fc1 83fa0a 0f9cc2 30da 08c1 80f101 08d1 }
            // n = 7, score = 700
            //   0f9fc1               | movzx               ecx, word ptr [edi + 2]
            //   83fa0a               | movzx               ebx, ax
            //   0f9cc2               | movzx               ecx, word ptr [edi + 8]
            //   30da                 | inc                 esp
            //   08c1                 | movzx               ebp, ax
            //   80f101               | movzx               ecx, word ptr [edi + 2]
            //   08d1                 | movzx               ebx, ax

        $sequence_35 = { 7528 0fb64b04 0fb6d1 80f973 }
            // n = 4, score = 700
            //   7528                 | cwde                
            //   0fb64b04             | dec                 eax
            //   0fb6d1               | mov                 ecx, esi
            //   80f973               | dec                 eax

        $sequence_36 = { 4889c1 31d2 4989f8 ff15???????? 4885c0 }
            // n = 5, score = 700
            //   4889c1               | mov                 eax, eax
            //   31d2                 | dec                 eax
            //   4989f8               | mov                 edx, ecx
            //   ff15????????         |                     
            //   4885c0               | dec                 eax

        $sequence_37 = { ff15???????? 31ed 4889c1 31d2 4989d8 }
            // n = 5, score = 700
            //   ff15????????         |                     
            //   31ed                 | dec                 esp
            //   4889c1               | mov                 eax, dword ptr [ecx + 0x40]
            //   31d2                 | dec                 eax
            //   4989d8               | mov                 edx, eax

        $sequence_38 = { 488bd3 e8???????? ff15???????? 4c8bc3 33d2 }
            // n = 5, score = 700
            //   488bd3               | mov                 ecx, esi
            //   e8????????           |                     
            //   ff15????????         |                     
            //   4c8bc3               | test                eax, eax
            //   33d2                 | dec                 eax

        $sequence_39 = { 0fb6d1 80f973 7504 0fb65305 }
            // n = 4, score = 700
            //   0fb6d1               | test                eax, eax
            //   80f973               | js                  0x16
            //   7504                 | dec                 eax
            //   0fb65305             | cwde                

        $sequence_40 = { 08c1 80f101 7502 ebfe }
            // n = 4, score = 700
            //   08c1                 | mov                 ebx, dword ptr [esp + 0x20]
            //   80f101               | dec                 eax
            //   7502                 | mov                 ecx, eax
            //   ebfe                 | xor                 edx, edx

        $sequence_41 = { e8???????? 4889f9 4889f2 ffd0 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   4889f9               | js                  0x13
            //   4889f2               | dec                 eax
            //   ffd0                 | cwde                

        $sequence_42 = { 0f9cc2 30da 7509 08c1 }
            // n = 4, score = 700
            //   0f9cc2               | movzx               ebp, ax
            //   30da                 | movzx               ecx, word ptr [edi + 8]
            //   7509                 | inc                 esp
            //   08c1                 | movzx               ebp, ax

        $sequence_43 = { 85da 0f94c3 83fd0a 0f9cc2 }
            // n = 4, score = 700
            //   85da                 | test                eax, eax
            //   0f94c3               | js                  0x13
            //   83fd0a               | dec                 eax
            //   0f9cc2               | cwde                

        $sequence_44 = { 84d2 7405 80fa2e 750f }
            // n = 4, score = 600
            //   84d2                 | dec                 eax
            //   7405                 | lea                 edx, [ebp + 0x7a0]
            //   80fa2e               | dec                 eax
            //   750f                 | lea                 eax, [esp + 0x70]

        $sequence_45 = { 4889c1 31d2 4d89e8 ff15???????? }
            // n = 4, score = 600
            //   4889c1               | inc                 ecx
            //   31d2                 | mov                 eax, 0x100f
            //   4d89e8               | dec                 eax
            //   ff15????????         |                     

        $sequence_46 = { 4889c1 31d2 4d89f8 ffd3 }
            // n = 4, score = 600
            //   4889c1               | test                eax, eax
            //   31d2                 | inc                 ecx
            //   4d89f8               | mov                 eax, 0x100f
            //   ffd3                 | dec                 eax

        $sequence_47 = { e8???????? 4c897c2420 4889d9 89fa }
            // n = 4, score = 600
            //   e8????????           |                     
            //   4c897c2420           | mov                 dword ptr [esp + 0x10], edx
            //   4889d9               | dec                 eax
            //   89fa                 | mov                 dword ptr [esp + 8], ecx

        $sequence_48 = { 89f0 4883c450 5b 5f }
            // n = 4, score = 600
            //   89f0                 | dec                 eax
            //   4883c450             | sub                 esp, 0x48
            //   5b                   | dec                 eax
            //   5f                   | mov                 dword ptr [esp + 0x30], 0

        $sequence_49 = { 8d4833 ff15???????? c744242810000000 4533c9 }
            // n = 4, score = 500
            //   8d4833               | lea                 edx, [ebp + 0x7a0]
            //   ff15????????         |                     
            //   c744242810000000     | dec                 eax
            //   4533c9               | lea                 eax, [esp + 0x70]

        $sequence_50 = { 6a00 56 ff15???????? 5f 5e 5d 8bc3 }
            // n = 7, score = 400
            //   6a00                 | push                esi
            //   56                   | push                0
            //   ff15????????         |                     
            //   5f                   | push                0x80
            //   5e                   | push                4
            //   5d                   | movzx               ecx, word ptr [edi]
            //   8bc3                 | movzx               ecx, word ptr [edi + 2]

        $sequence_51 = { 689c7d9d93 6a04 5a e8???????? 59 59 85c0 }
            // n = 7, score = 400
            //   689c7d9d93           | mov                 dword ptr [esp + 0x58], eax
            //   6a04                 | dec                 eax
            //   5a                   | lea                 ecx, [eax + 1]
            //   e8????????           |                     
            //   59                   | push                eax
            //   59                   | movzx               eax, word ptr [ebp - 0x18]
            //   85c0                 | push                eax

        $sequence_52 = { 8d44244c 50 6a00 ff74243c 53 55 ff15???????? }
            // n = 7, score = 400
            //   8d44244c             | jne                 0xd
            //   50                   | mov                 al, cl
            //   6a00                 | sub                 al, dl
            //   ff74243c             | dec                 al
            //   53                   | mov                 byte ptr [edx + ebx], al
            //   55                   | lea                 eax, [edi + 1]
            //   ff15????????         |                     

        $sequence_53 = { 6685ff 0f849c000000 837c2460ff 0f858c000000 }
            // n = 4, score = 400
            //   6685ff               | dec                 eax
            //   0f849c000000         | cwde                
            //   837c2460ff           | dec                 eax
            //   0f858c000000         | mov                 dword ptr [esp + 0x20], eax

        $sequence_54 = { 50 0fb745e8 50 68???????? e8???????? }
            // n = 5, score = 400
            //   50                   | inc                 ebp
            //   0fb745e8             | xor                 ecx, ecx
            //   50                   | dec                 eax
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_55 = { 66890d???????? 0fb7ca ff15???????? b901000000 66c746020100 668906 }
            // n = 6, score = 400
            //   66890d????????       |                     
            //   0fb7ca               | dec                 eax
            //   ff15????????         |                     
            //   b901000000           | mov                 ecx, esi
            //   66c746020100         | dec                 eax
            //   668906               | mov                 dword ptr [esp + 0x20], eax

        $sequence_56 = { 7506 8b0e 894c2460 0fb7c0 }
            // n = 4, score = 400
            //   7506                 | dec                 eax
            //   8b0e                 | mov                 dword ptr [esp + 0x20], eax
            //   894c2460             | test                eax, eax
            //   0fb7c0               | js                  0x1c

        $sequence_57 = { 8a842483030000 81fe80000000 760b 24f2 0c02 }
            // n = 5, score = 400
            //   8a842483030000       | test                cl, cl
            //   81fe80000000         | cmovne              eax, edi
            //   760b                 | cmp                 byte ptr [edx], 0
            //   24f2                 | mov                 edi, eax
            //   0c02                 | push                dword ptr [ebp + 8]

        $sequence_58 = { 57 8d4101 6a0e 8bf0 5f 8a11 }
            // n = 6, score = 400
            //   57                   | push                eax
            //   8d4101               | movzx               eax, word ptr [ebp - 0x16]
            //   6a0e                 | push                eax
            //   8bf0                 | movzx               eax, word ptr [ebp - 0x18]
            //   5f                   | push                eax
            //   8a11                 | movzx               eax, word ptr [ebp - 0x16]

        $sequence_59 = { 7406 6a35 ffd0 eb02 33c0 }
            // n = 5, score = 400
            //   7406                 | push                eax
            //   6a35                 | movzx               eax, word ptr [ebp - 0x18]
            //   ffd0                 | push                eax
            //   eb02                 | movzx               eax, word ptr [ebp - 0x18]
            //   33c0                 | push                eax

        $sequence_60 = { ffd6 8d7001 56 6a08 ff15???????? 50 }
            // n = 6, score = 300
            //   ffd6                 | je                  0x11
            //   8d7001               | xor                 edx, edx
            //   56                   | cmp                 ecx, 2
            //   6a08                 | setne               dl
            //   ff15????????         |                     
            //   50                   | je                  0x1b

        $sequence_61 = { 740d 33d2 83f902 0f95c2 83c224 }
            // n = 5, score = 300
            //   740d                 | mov                 ecx, eax
            //   33d2                 | dec                 ebp
            //   83f902               | mov                 eax, ebp
            //   0f95c2               | xor                 edx, edx
            //   83c224               | dec                 eax

        $sequence_62 = { 0f95c2 83c224 eb05 ba29000000 }
            // n = 4, score = 300
            //   0f95c2               | mov                 ecx, eax
            //   83c224               | inc                 ebp
            //   eb05                 | xor                 ecx, ecx
            //   ba29000000           | inc                 ebp

        $sequence_63 = { 660f73d801 660febd0 660f7ed0 84c0 }
            // n = 4, score = 300
            //   660f73d801           | add                 edx, 0x24
            //   660febd0             | jmp                 0x12
            //   660f7ed0             | mov                 edx, 0x29
            //   84c0                 | test                edx, edx

        $sequence_64 = { 750b 8ac1 2ac2 fec8 88041a }
            // n = 5, score = 300
            //   750b                 | inc                 ecx
            //   8ac1                 | mov                 eax, 0x100f
            //   2ac2                 | dec                 eax
            //   fec8                 | mov                 ecx, esi
            //   88041a               | dec                 eax

        $sequence_65 = { 8d4701 84c9 0f45c7 803a00 8bf8 }
            // n = 5, score = 300
            //   8d4701               | mov                 dword ptr [esp + 0x20], eax
            //   84c9                 | test                eax, eax
            //   0f45c7               | movzx               ecx, cl
            //   803a00               | dec                 eax
            //   8bf8                 | sub                 ecx, 0xc0

        $sequence_66 = { 6a00 6a00 50 8d4601 }
            // n = 4, score = 300
            //   6a00                 | cmp                 ecx, 2
            //   6a00                 | setne               dl
            //   50                   | add                 edx, 0x24
            //   8d4601               | setne               dl

        $sequence_67 = { c1f808 0fb6c0 50 0fb6c2 }
            // n = 4, score = 300
            //   c1f808               | xor                 edx, edx
            //   0fb6c0               | cmp                 ecx, 2
            //   50                   | setne               dl
            //   0fb6c2               | add                 edx, 0x24

        $sequence_68 = { 83c410 b800308804 6a00 50 }
            // n = 4, score = 300
            //   83c410               | add                 edx, 0x24
            //   b800308804           | jmp                 0xd
            //   6a00                 | mov                 edx, 0x29
            //   50                   | test                edx, edx

        $sequence_69 = { 81feff030000 733c 8a02 3cc0 721e 0fb6c8 }
            // n = 6, score = 300
            //   81feff030000         | je                  0x11
            //   733c                 | xor                 edx, edx
            //   8a02                 | cmp                 ecx, 2
            //   3cc0                 | test                edx, edx
            //   721e                 | je                  0x1a
            //   0fb6c8               | xor                 edx, edx

        $sequence_70 = { 89542410 48894c2408 4883ec48 8b442458 89442424 48c744242800000000 }
            // n = 6, score = 100
            //   89542410             | lea                 ecx, [eax + 0x33]
            //   48894c2408           | mov                 dword ptr [esp + 0x28], 0x10
            //   4883ec48             | inc                 ebp
            //   8b442458             | xor                 ecx, ecx
            //   89442424             | dec                 ebp
            //   48c744242800000000     | mov    eax, ebp

        $sequence_71 = { 488b442430 488b8c2410010000 48894830 488b442430 488b8c2418010000 48894838 488b442430 }
            // n = 7, score = 100
            //   488b442430           | inc                 ecx
            //   488b8c2410010000     | mov                 eax, 0x100f
            //   48894830             | dec                 eax
            //   488b442430           | mov                 ecx, esi
            //   488b8c2418010000     | dec                 eax
            //   48894838             | mov                 dword ptr [esp + 0x20], eax
            //   488b442430           | test                eax, eax

        $sequence_72 = { 488bca 448bc0 488bd1 488b4c2430 e8???????? 488b442428 }
            // n = 6, score = 100
            //   488bca               | mov                 esi, eax
            //   448bc0               | dec                 eax
            //   488bd1               | mov                 dword ptr [esp + 0x58], eax
            //   488b4c2430           | dec                 eax
            //   e8????????           |                     
            //   488b442428           | lea                 ecx, [eax + 1]

        $sequence_73 = { ff15???????? 33c0 eb47 488b442430 8b4014 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   33c0                 | mov                 ecx, esi
            //   eb47                 | dec                 eax
            //   488b442430           | mov                 dword ptr [esp + 0x20], eax
            //   8b4014               | test                eax, eax

        $sequence_74 = { 4825ffff0000 488b8c2488000000 4c8b4140 488bd0 }
            // n = 4, score = 100
            //   4825ffff0000         | xor                 edx, edx
            //   488b8c2488000000     | dec                 eax
            //   4c8b4140             | mov                 ecx, eax
            //   488bd0               | dec                 esp

        $sequence_75 = { 488b442430 48c7404800000000 488b442430 eb14 }
            // n = 4, score = 100
            //   488b442430           | js                  0x16
            //   48c7404800000000     | inc                 ecx
            //   488b442430           | mov                 eax, 0x100f
            //   eb14                 | dec                 eax

        $sequence_76 = { eb1f 488b442430 8b4024 2580000000 }
            // n = 4, score = 100
            //   eb1f                 | je                  7
            //   488b442430           | cmp                 dl, 0x2e
            //   8b4024               | jne                 0x16
            //   2580000000           | movzx               eax, cl

        $sequence_77 = { 488b442458 488b00 b908000000 486bc909 488d840888000000 4889442428 488b442428 }
            // n = 7, score = 100
            //   488b442458           | cmp                 dl, 0x2e
            //   488b00               | jne                 0x18
            //   b908000000           | je                  7
            //   486bc909             | cmp                 dl, 0x2e
            //   488d840888000000     | jne                 0x14
            //   4889442428           | movzx               eax, cl
            //   488b442428           | test                dl, dl

    condition:
        7 of them and filesize < 2088960
}