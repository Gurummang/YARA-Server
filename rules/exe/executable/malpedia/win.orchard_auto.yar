rule win_orchard_auto {

    meta:
        atk_type = "win.orchard."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.orchard."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.orchard"
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
        $sequence_0 = { 83c404 e8???????? 99 b95b000000 f7f9 }
            // n = 5, score = 200
            //   83c404               | add                 esp, 4
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b95b000000           | mov                 ecx, 0x5b
            //   f7f9                 | idiv                ecx

        $sequence_1 = { 6a01 c645fc08 e8???????? 894604 83c404 8d4718 897034 }
            // n = 7, score = 200
            //   6a01                 | push                1
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   e8????????           |                     
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   83c404               | add                 esp, 4
            //   8d4718               | lea                 eax, [edi + 0x18]
            //   897034               | mov                 dword ptr [eax + 0x34], esi

        $sequence_2 = { 56 ff15???????? ff15???????? 50 6a00 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_3 = { 8b8550fdffff 83e001 0f8412000000 83a550fdfffffe }
            // n = 4, score = 200
            //   8b8550fdffff         | mov                 eax, dword ptr [ebp - 0x2b0]
            //   83e001               | and                 eax, 1
            //   0f8412000000         | je                  0x18
            //   83a550fdfffffe       | and                 dword ptr [ebp - 0x2b0], 0xfffffffe

        $sequence_4 = { 8a45ef 884740 7510 8b470c 8bcf 6a00 }
            // n = 6, score = 200
            //   8a45ef               | mov                 al, byte ptr [ebp - 0x11]
            //   884740               | mov                 byte ptr [edi + 0x40], al
            //   7510                 | jne                 0x12
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   8bcf                 | mov                 ecx, edi
            //   6a00                 | push                0

        $sequence_5 = { 8d442410 50 ff15???????? 6685c0 }
            // n = 4, score = 200
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6685c0               | test                ax, ax

        $sequence_6 = { 8b5de8 894348 8b5de0 c70600000000 }
            // n = 4, score = 200
            //   8b5de8               | mov                 ebx, dword ptr [ebp - 0x18]
            //   894348               | mov                 dword ptr [ebx + 0x48], eax
            //   8b5de0               | mov                 ebx, dword ptr [ebp - 0x20]
            //   c70600000000         | mov                 dword ptr [esi], 0

        $sequence_7 = { 8b75a8 46 56 e8???????? }
            // n = 4, score = 200
            //   8b75a8               | mov                 esi, dword ptr [ebp - 0x58]
            //   46                   | inc                 esi
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_8 = { 8b54240c 83d200 03c1 8b4c2420 }
            // n = 4, score = 200
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   83d200               | adc                 edx, 0
            //   03c1                 | add                 eax, ecx
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]

        $sequence_9 = { f7f9 81c2d0070000 52 ffd6 }
            // n = 4, score = 200
            //   f7f9                 | idiv                ecx
            //   81c2d0070000         | add                 edx, 0x7d0
            //   52                   | push                edx
            //   ffd6                 | call                esi

        $sequence_10 = { 8b10 8bc8 6a01 ff12 837f3800 8a45ef }
            // n = 6, score = 200
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8bc8                 | mov                 ecx, eax
            //   6a01                 | push                1
            //   ff12                 | call                dword ptr [edx]
            //   837f3800             | cmp                 dword ptr [edi + 0x38], 0
            //   8a45ef               | mov                 al, byte ptr [ebp - 0x11]

        $sequence_11 = { 8b07 6a08 895de0 8b4004 }
            // n = 4, score = 200
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   6a08                 | push                8
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

        $sequence_12 = { 83f81f 0f877e030000 52 51 e8???????? }
            // n = 5, score = 200
            //   83f81f               | cmp                 eax, 0x1f
            //   0f877e030000         | ja                  0x384
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_13 = { 8b7c2424 89542428 8b54240c 83d200 }
            // n = 4, score = 200
            //   8b7c2424             | mov                 edi, dword ptr [esp + 0x24]
            //   89542428             | mov                 dword ptr [esp + 0x28], edx
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   83d200               | adc                 edx, 0

        $sequence_14 = { 50 ff15???????? 83f805 7507 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83f805               | cmp                 eax, 5
            //   7507                 | jne                 9

        $sequence_15 = { 8bc8 83e01f c1f905 8b0c8d00755d00 c1e006 8d44010c 50 }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d00755d00       | mov                 ecx, dword ptr [ecx*4 + 0x5d7500]
            //   c1e006               | shl                 eax, 6
            //   8d44010c             | lea                 eax, [ecx + eax + 0xc]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 4716352
}