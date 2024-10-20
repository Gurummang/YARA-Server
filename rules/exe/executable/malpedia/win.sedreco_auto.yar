rule win_sedreco_auto {

    meta:
        atk_type = "win.sedreco."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sedreco."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sedreco"
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
        $sequence_0 = { e8???????? 89450c 56 85c0 }
            // n = 4, score = 2600
            //   e8????????           |                     
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   56                   | push                esi
            //   85c0                 | test                eax, eax

        $sequence_1 = { c645ff30 e8???????? 85c0 7505 }
            // n = 4, score = 2600
            //   c645ff30             | mov                 byte ptr [ebp - 1], 0x30
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7

        $sequence_2 = { 8bec 51 836d0804 53 }
            // n = 4, score = 2600
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   836d0804             | sub                 dword ptr [ebp + 8], 4
            //   53                   | push                ebx

        $sequence_3 = { 836d0804 53 56 8b750c }
            // n = 4, score = 2600
            //   836d0804             | sub                 dword ptr [ebp + 8], 4
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]

        $sequence_4 = { 8b750c 56 e8???????? 6a08 }
            // n = 4, score = 2600
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a08                 | push                8

        $sequence_5 = { 50 68???????? 6a0d 68???????? }
            // n = 4, score = 2500
            //   50                   | push                eax
            //   68????????           |                     
            //   6a0d                 | push                0xd
            //   68????????           |                     

        $sequence_6 = { 51 6802020000 68???????? 50 }
            // n = 4, score = 2400
            //   51                   | push                ecx
            //   6802020000           | push                0x202
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_7 = { 7411 6a04 68???????? 68???????? }
            // n = 4, score = 2400
            //   7411                 | je                  0x13
            //   6a04                 | push                4
            //   68????????           |                     
            //   68????????           |                     

        $sequence_8 = { 7ce0 a1???????? 5e 85c0 }
            // n = 4, score = 2400
            //   7ce0                 | jl                  0xffffffe2
            //   a1????????           |                     
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax

        $sequence_9 = { ff15???????? 83c604 81fe???????? 7ce0 }
            // n = 4, score = 2200
            //   ff15????????         |                     
            //   83c604               | add                 esi, 4
            //   81fe????????         |                     
            //   7ce0                 | jl                  0xffffffe2

        $sequence_10 = { ffd6 8b0d???????? 898114010000 85c0 }
            // n = 4, score = 2200
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   898114010000         | mov                 dword ptr [ecx + 0x114], eax
            //   85c0                 | test                eax, eax

        $sequence_11 = { ffd6 8b0d???????? 898198000000 85c0 }
            // n = 4, score = 2200
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   898198000000         | mov                 dword ptr [ecx + 0x98], eax
            //   85c0                 | test                eax, eax

        $sequence_12 = { 56 be???????? 8b06 85c0 740f 50 }
            // n = 6, score = 2200
            //   56                   | push                esi
            //   be????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   50                   | push                eax

        $sequence_13 = { ffd6 8b0d???????? 894160 85c0 }
            // n = 4, score = 2200
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   894160               | mov                 dword ptr [ecx + 0x60], eax
            //   85c0                 | test                eax, eax

        $sequence_14 = { ffd6 ffd0 a3???????? 5e 85c0 750a a1???????? }
            // n = 7, score = 2200
            //   ffd6                 | call                esi
            //   ffd0                 | call                eax
            //   a3????????           |                     
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   a1????????           |                     

        $sequence_15 = { 6a01 68???????? ff35???????? ff15???????? ffd0 }
            // n = 5, score = 1100
            //   6a01                 | push                1
            //   68????????           |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   ffd0                 | call                eax

        $sequence_16 = { 488b05???????? ff90e8000000 90 4883c420 }
            // n = 4, score = 500
            //   488b05????????       |                     
            //   ff90e8000000         | mov                 ecx, 0x80000001
            //   90                   | call                dword ptr [eax + 0x138]
            //   4883c420             | dec                 eax

        $sequence_17 = { 68???????? e8???????? 8b35???????? 83c404 6a00 68???????? 6aff }
            // n = 7, score = 500
            //   68????????           |                     
            //   e8????????           |                     
            //   8b35????????         |                     
            //   83c404               | add                 esi, 4
            //   6a00                 | jl                  0xffffffe2
            //   68????????           |                     
            //   6aff                 | pop                 esi

        $sequence_18 = { 4889442420 41b906000200 4533c0 488b15???????? 48c7c101000080 488b05???????? ff9038010000 }
            // n = 7, score = 500
            //   4889442420           | xor                 edx, edx
            //   41b906000200         | dec                 eax
            //   4533c0               | lea                 ecx, [esp + 0x50]
            //   488b15????????       |                     
            //   48c7c101000080       | call                dword ptr [eax + 0x2d8]
            //   488b05????????       |                     
            //   ff9038010000         | dec                 eax

        $sequence_19 = { 6800010000 6a00 68???????? e8???????? 6800020000 }
            // n = 5, score = 500
            //   6800010000           | pop                 esi
            //   6a00                 | test                eax, eax
            //   68????????           |                     
            //   e8????????           |                     
            //   6800020000           | add                 esi, 4

        $sequence_20 = { ffd6 50 68???????? 6aff }
            // n = 4, score = 500
            //   ffd6                 | jl                  0xffffffe2
            //   50                   | pop                 esi
            //   68????????           |                     
            //   6aff                 | test                eax, eax

        $sequence_21 = { 488b0d???????? 488b05???????? ff5010 85c0 }
            // n = 4, score = 500
            //   488b0d????????       |                     
            //   488b05????????       |                     
            //   ff5010               | mov                 edx, 0xc0000000
            //   85c0                 | call                dword ptr [eax + 0x40]

        $sequence_22 = { 50 68???????? 6aff 68???????? 6a00 6a00 ffd6 }
            // n = 7, score = 500
            //   50                   | test                eax, eax
            //   68????????           |                     
            //   6aff                 | jne                 9
            //   68????????           |                     
            //   6a00                 | mov                 ebp, esp
            //   6a00                 | push                ecx
            //   ffd6                 | sub                 dword ptr [ebp + 8], 4

        $sequence_23 = { 4883c428 c3 48890d???????? c3 48895c2410 4889742418 55 }
            // n = 7, score = 500
            //   4883c428             | dec                 eax
            //   c3                   | add                 esp, 0x28
            //   48890d????????       |                     
            //   c3                   | ret                 
            //   48895c2410           | ret                 
            //   4889742418           | dec                 eax
            //   55                   | mov                 dword ptr [esp + 0x10], ebx

        $sequence_24 = { 33d2 488d4c2450 488b05???????? ff90d8020000 }
            // n = 4, score = 500
            //   33d2                 | dec                 eax
            //   488d4c2450           | mov                 dword ptr [esp + 0x18], esi
            //   488b05????????       |                     
            //   ff90d8020000         | push                ebp

        $sequence_25 = { 4533c9 4533c0 ba000000c0 488b0d???????? 488b05???????? ff5040 }
            // n = 6, score = 500
            //   4533c9               | add                 eax, 0x10
            //   4533c0               | dec                 eax
            //   ba000000c0           | add                 esp, 0x28
            //   488b0d????????       |                     
            //   488b05????????       |                     
            //   ff5040               | ret                 

        $sequence_26 = { 448bc0 ba08000000 488b0d???????? ff15???????? 488905???????? }
            // n = 5, score = 500
            //   448bc0               | dec                 eax
            //   ba08000000           | add                 esp, 0x28
            //   488b0d????????       |                     
            //   ff15????????         |                     
            //   488905????????       |                     

        $sequence_27 = { 488b0d???????? 488b05???????? ff5028 48c705????????00000000 }
            // n = 4, score = 500
            //   488b0d????????       |                     
            //   488b05????????       |                     
            //   ff5028               | inc                 ebp
            //   48c705????????00000000     |     

        $sequence_28 = { ffd6 8b4dfc 5f 5e 33cd b8???????? }
            // n = 6, score = 400
            //   ffd6                 | call                esi
            //   8b4dfc               | push                eax
            //   5f                   | push                -1
            //   5e                   | add                 esp, 4
            //   33cd                 | push                0
            //   b8????????           |                     

        $sequence_29 = { 7cd5 68???????? e8???????? 8b4dfc 83c404 }
            // n = 5, score = 400
            //   7cd5                 | push                0
            //   68????????           |                     
            //   e8????????           |                     
            //   8b4dfc               | push                -1
            //   83c404               | push                0

        $sequence_30 = { 53 68???????? ff35???????? ffd6 ffd0 85c0 }
            // n = 6, score = 400
            //   53                   | push                ebx
            //   68????????           |                     
            //   ff35????????         |                     
            //   ffd6                 | call                esi
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax

        $sequence_31 = { e8???????? 8b8c2424020000 5b 33cc 33c0 e8???????? }
            // n = 6, score = 300
            //   e8????????           |                     
            //   8b8c2424020000       | push                0
            //   5b                   | call                esi
            //   33cc                 | mov                 ecx, dword ptr [ebp - 4]
            //   33c0                 | pop                 edi
            //   e8????????           |                     

        $sequence_32 = { 52 50 ff91f0000000 8bf0 }
            // n = 4, score = 300
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff91f0000000         | call                dword ptr [ecx + 0xf0]
            //   8bf0                 | mov                 esi, eax

        $sequence_33 = { a1???????? 33c5 8945fc 6a0a 8d45f4 50 51 }
            // n = 7, score = 300
            //   a1????????           |                     
            //   33c5                 | push                0
            //   8945fc               | call                esi
            //   6a0a                 | add                 esp, 4
            //   8d45f4               | push                0
            //   50                   | push                -1
            //   51                   | push                0

        $sequence_34 = { 8d55f8 52 50 8b08 ff5124 }
            // n = 5, score = 300
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5124               | call                dword ptr [ecx + 0x24]

        $sequence_35 = { c20c00 6a02 ff74240c ff74240c e8???????? c20800 ff74240c }
            // n = 7, score = 300
            //   c20c00               | ret                 0xc
            //   6a02                 | push                2
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   e8????????           |                     
            //   c20800               | ret                 8
            //   ff74240c             | push                dword ptr [esp + 0xc]

        $sequence_36 = { 57 50 ff512c 8bce }
            // n = 4, score = 200
            //   57                   | push                edi
            //   50                   | push                eax
            //   ff512c               | call                dword ptr [ecx + 0x2c]
            //   8bce                 | mov                 ecx, esi

        $sequence_37 = { ff512c 8bf0 f7de 1bf6 46 }
            // n = 5, score = 200
            //   ff512c               | call                dword ptr [ecx + 0x2c]
            //   8bf0                 | mov                 esi, eax
            //   f7de                 | neg                 esi
            //   1bf6                 | sbb                 esi, esi
            //   46                   | inc                 esi

        $sequence_38 = { 8945fc 8b45f0 8945f4 8b45f4 }
            // n = 4, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_39 = { 50 8b08 ff9180000000 8b06 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff9180000000         | call                dword ptr [ecx + 0x80]
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_40 = { ff512c 8bce 8bd8 e8???????? 57 }
            // n = 5, score = 200
            //   ff512c               | call                dword ptr [ecx + 0x2c]
            //   8bce                 | mov                 ecx, esi
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   57                   | push                edi

        $sequence_41 = { 57 c785ecfeffff01000000 c785e8feffffe197af54 0f6e85e8feffff 0f72f002 }
            // n = 5, score = 200
            //   57                   | push                edi
            //   c785ecfeffff01000000     | mov    dword ptr [ebp - 0x114], 1
            //   c785e8feffffe197af54     | mov    dword ptr [ebp - 0x118], 0x54af97e1
            //   0f6e85e8feffff       | movd                mm0, dword ptr [ebp - 0x118]
            //   0f72f002             | pslld               mm0, 2

        $sequence_42 = { 83ec24 53 56 57 c745dce197af54 }
            // n = 5, score = 200
            //   83ec24               | sub                 esp, 0x24
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   c745dce197af54       | mov                 dword ptr [ebp - 0x24], 0x54af97e1

        $sequence_43 = { 8d443001 6a00 51 50 }
            // n = 4, score = 200
            //   8d443001             | lea                 eax, [eax + esi + 1]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_44 = { 8d7901 8d4c2420 57 ff15???????? 84c0 }
            // n = 5, score = 100
            //   8d7901               | mov                 eax, dword ptr [esi]
            //   8d4c2420             | test                eax, eax
            //   57                   | je                  0x13
            //   ff15????????         |                     
            //   84c0                 | push                eax

        $sequence_45 = { 6800040000 51 56 8974242c ff15???????? 85c0 0f8484010000 }
            // n = 7, score = 100
            //   6800040000           | add                 esi, 4
            //   51                   | jl                  0xffffffe2
            //   56                   | call                esi
            //   8974242c             | mov                 dword ptr [ecx + 0xe4], eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8484010000         | call                dword ptr [eax + 0xe8]

        $sequence_46 = { 51 52 ff15???????? 8b442410 8b4e10 }
            // n = 5, score = 100
            //   51                   | mov                 edx, 0x2710
            //   52                   | call                dword ptr [eax + 0x10]
            //   ff15????????         |                     
            //   8b442410             | jmp                 6
            //   8b4e10               | dec                 eax

        $sequence_47 = { a1???????? 8b00 8b4c2420 88440c18 }
            // n = 4, score = 100
            //   a1????????           |                     
            //   8b00                 | jl                  0xffffffe2
            //   8b4c2420             | pop                 esi
            //   88440c18             | test                eax, eax

        $sequence_48 = { 85db 7548 fec8 53 b9???????? 8842ff }
            // n = 6, score = 100
            //   85db                 | ret                 
            //   7548                 | dec                 eax
            //   fec8                 | mov                 dword ptr [esp + 0x10], ebx
            //   53                   | dec                 eax
            //   b9????????           |                     
            //   8842ff               | add                 eax, 0x10

        $sequence_49 = { e8???????? 8a54240b 83c404 8b4c2430 895c2410 3bcb }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8a54240b             | call                dword ptr [eax + 0xe8]
            //   83c404               | nop                 
            //   8b4c2430             | dec                 eax
            //   895c2410             | add                 esp, 0x20
            //   3bcb                 | xor                 edx, edx

        $sequence_50 = { 52 56 50 ff15???????? 6a01 }
            // n = 5, score = 100
            //   52                   | add                 eax, 0x10
            //   56                   | dec                 eax
            //   50                   | add                 esp, 0x28
            //   ff15????????         |                     
            //   6a01                 | ret                 

        $sequence_51 = { 8d442428 c684244010000001 8b11 8d4c2418 52 56 }
            // n = 6, score = 100
            //   8d442428             | dec                 eax
            //   c684244010000001     | add                 esp, 0x28
            //   8b11                 | ret                 
            //   8d4c2418             | ret                 
            //   52                   | dec                 eax
            //   56                   | mov                 dword ptr [esp + 0x10], ebx

    condition:
        7 of them and filesize < 1586176
}