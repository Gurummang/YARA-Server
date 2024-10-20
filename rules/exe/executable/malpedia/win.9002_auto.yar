rule win_9002_auto {

    meta:
        atk_type = "win.9002."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.9002."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.9002"
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
        $sequence_0 = { 7514 8b4714 8b08 51 e8???????? 8b5714 }
            // n = 6, score = 200
            //   7514                 | jne                 0x16
            //   8b4714               | mov                 eax, dword ptr [edi + 0x14]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b5714               | mov                 edx, dword ptr [edi + 0x14]

        $sequence_1 = { 51 8944241c c744241801000000 ff15???????? 3d02010000 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   c744241801000000     | mov                 dword ptr [esp + 0x18], 1
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102

        $sequence_2 = { 7504 33ed eb04 2bc8 }
            // n = 4, score = 200
            //   7504                 | jne                 6
            //   33ed                 | xor                 ebp, ebp
            //   eb04                 | jmp                 6
            //   2bc8                 | sub                 ecx, eax

        $sequence_3 = { 8bd1 2bd0 3bda 7223 }
            // n = 4, score = 200
            //   8bd1                 | mov                 edx, ecx
            //   2bd0                 | sub                 edx, eax
            //   3bda                 | cmp                 ebx, edx
            //   7223                 | jb                  0x25

        $sequence_4 = { 6a02 ff15???????? 68???????? ff15???????? 6a00 }
            // n = 5, score = 200
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_5 = { 8b5c2408 6bdb08 03c3 8b00 }
            // n = 4, score = 200
            //   8b5c2408             | mov                 ebx, dword ptr [esp + 8]
            //   6bdb08               | imul                ebx, ebx, 8
            //   03c3                 | add                 eax, ebx
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_6 = { 33c9 3bc8 1bd2 f7da 8915???????? }
            // n = 5, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   3bc8                 | cmp                 ecx, eax
            //   1bd2                 | sbb                 edx, edx
            //   f7da                 | neg                 edx
            //   8915????????         |                     

        $sequence_7 = { 03c3 8b00 5b ffd0 8945fc }
            // n = 5, score = 200
            //   03c3                 | add                 eax, ebx
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   5b                   | pop                 ebx
            //   ffd0                 | call                eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_8 = { 51 e8???????? 6a06 6a01 6a02 e8???????? }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   6a06                 | push                6
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   e8????????           |                     

        $sequence_9 = { 8be9 53 50 e8???????? }
            // n = 4, score = 200
            //   8be9                 | mov                 ebp, ecx
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_10 = { 7504 33d2 eb05 8b5608 2bd0 3bfa }
            // n = 6, score = 200
            //   7504                 | jne                 6
            //   33d2                 | xor                 edx, edx
            //   eb05                 | jmp                 7
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   2bd0                 | sub                 edx, eax
            //   3bfa                 | cmp                 edi, edx

        $sequence_11 = { 682c010000 50 ffd3 3d02010000 7508 }
            // n = 5, score = 200
            //   682c010000           | push                0x12c
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   3d02010000           | cmp                 eax, 0x102
            //   7508                 | jne                 0xa

        $sequence_12 = { 6a00 6a02 6a03 6a00 e8???????? }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_13 = { 75f6 eb2f 8b542430 8b7c2414 8b6c2430 }
            // n = 5, score = 100
            //   75f6                 | jne                 0xfffffff8
            //   eb2f                 | jmp                 0x31
            //   8b542430             | mov                 edx, dword ptr [esp + 0x30]
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   8b6c2430             | mov                 ebp, dword ptr [esp + 0x30]

        $sequence_14 = { 668b3c59 730d 33c9 8a0a }
            // n = 4, score = 100
            //   668b3c59             | mov                 di, word ptr [ecx + ebx*2]
            //   730d                 | jae                 0xf
            //   33c9                 | xor                 ecx, ecx
            //   8a0a                 | mov                 cl, byte ptr [edx]

        $sequence_15 = { 59 8b0485e0d50010 8d0cf6 8064880400 85ff }
            // n = 5, score = 100
            //   59                   | pop                 ecx
            //   8b0485e0d50010       | mov                 eax, dword ptr [eax*4 + 0x1000d5e0]
            //   8d0cf6               | lea                 ecx, [esi + esi*8]
            //   8064880400           | and                 byte ptr [eax + ecx*4 + 4], 0
            //   85ff                 | test                edi, edi

        $sequence_16 = { 0311 8955fc 837df800 0f86e3000000 8b4508 03450c 2b45f8 }
            // n = 7, score = 100
            //   0311                 | add                 edx, dword ptr [ecx]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   0f86e3000000         | jbe                 0xe9
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   03450c               | add                 eax, dword ptr [ebp + 0xc]
            //   2b45f8               | sub                 eax, dword ptr [ebp - 8]

        $sequence_17 = { 68???????? 8d4610 50 8d4c2418 51 ff15???????? }
            // n = 6, score = 100
            //   68????????           |                     
            //   8d4610               | lea                 eax, [esi + 0x10]
            //   50                   | push                eax
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_18 = { 896f2c 8b4748 3bc5 740c 50 }
            // n = 5, score = 100
            //   896f2c               | mov                 dword ptr [edi + 0x2c], ebp
            //   8b4748               | mov                 eax, dword ptr [edi + 0x48]
            //   3bc5                 | cmp                 eax, ebp
            //   740c                 | je                  0xe
            //   50                   | push                eax

        $sequence_19 = { 8d4c240c c644243002 ff15???????? 8bc6 }
            // n = 4, score = 100
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   c644243002           | mov                 byte ptr [esp + 0x30], 2
            //   ff15????????         |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_20 = { 6a00 8bd8 51 57 53 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   8bd8                 | mov                 ebx, eax
            //   51                   | push                ecx
            //   57                   | push                edi
            //   53                   | push                ebx

        $sequence_21 = { 8b4c242c 5f 89411c 8b442410 895118 8b542434 894124 }
            // n = 7, score = 100
            //   8b4c242c             | mov                 ecx, dword ptr [esp + 0x2c]
            //   5f                   | pop                 edi
            //   89411c               | mov                 dword ptr [ecx + 0x1c], eax
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   895118               | mov                 dword ptr [ecx + 0x18], edx
            //   8b542434             | mov                 edx, dword ptr [esp + 0x34]
            //   894124               | mov                 dword ptr [ecx + 0x24], eax

        $sequence_22 = { 33c4 50 8d442428 64a300000000 8bf1 89742408 68???????? }
            // n = 7, score = 100
            //   33c4                 | xor                 eax, esp
            //   50                   | push                eax
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf1                 | mov                 esi, ecx
            //   89742408             | mov                 dword ptr [esp + 8], esi
            //   68????????           |                     

        $sequence_23 = { 8939 89742410 e9???????? 33f6 83ff14 }
            // n = 5, score = 100
            //   8939                 | mov                 dword ptr [ecx], edi
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   e9????????           |                     
            //   33f6                 | xor                 esi, esi
            //   83ff14               | cmp                 edi, 0x14

        $sequence_24 = { 0fb74e08 0fafcf 5f 03c1 5e }
            // n = 5, score = 100
            //   0fb74e08             | movzx               ecx, word ptr [esi + 8]
            //   0fafcf               | imul                ecx, edi
            //   5f                   | pop                 edi
            //   03c1                 | add                 eax, ecx
            //   5e                   | pop                 esi

        $sequence_25 = { 031481 52 8b450c 50 }
            // n = 4, score = 100
            //   031481               | add                 edx, dword ptr [ecx + eax*4]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax

        $sequence_26 = { 5d 83c410 c3 8b4508 85c0 7499 }
            // n = 6, score = 100
            //   5d                   | pop                 ebp
            //   83c410               | add                 esp, 0x10
            //   c3                   | ret                 
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   85c0                 | test                eax, eax
            //   7499                 | je                  0xffffff9b

        $sequence_27 = { 2bc5 c1ef05 2bcf 2bf5 66898c5a98010000 33c9 }
            // n = 6, score = 100
            //   2bc5                 | sub                 eax, ebp
            //   c1ef05               | shr                 edi, 5
            //   2bcf                 | sub                 ecx, edi
            //   2bf5                 | sub                 esi, ebp
            //   66898c5a98010000     | mov                 word ptr [edx + ebx*2 + 0x198], cx
            //   33c9                 | xor                 ecx, ecx

        $sequence_28 = { 64a300000000 8b7c2444 8bf1 33db 57 8d4e10 89742414 }
            // n = 7, score = 100
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b7c2444             | mov                 edi, dword ptr [esp + 0x44]
            //   8bf1                 | mov                 esi, ecx
            //   33db                 | xor                 ebx, ebx
            //   57                   | push                edi
            //   8d4e10               | lea                 ecx, [esi + 0x10]
            //   89742414             | mov                 dword ptr [esp + 0x14], esi

        $sequence_29 = { 8b742408 57 85f6 742e 0fb74602 8b7c2410 3bf8 }
            // n = 7, score = 100
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   57                   | push                edi
            //   85f6                 | test                esi, esi
            //   742e                 | je                  0x30
            //   0fb74602             | movzx               eax, word ptr [esi + 2]
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   3bf8                 | cmp                 edi, eax

        $sequence_30 = { 8b5c2424 3bcb 0f83f6040000 33db }
            // n = 4, score = 100
            //   8b5c2424             | mov                 ebx, dword ptr [esp + 0x24]
            //   3bcb                 | cmp                 ecx, ebx
            //   0f83f6040000         | jae                 0x4fc
            //   33db                 | xor                 ebx, ebx

    condition:
        7 of them and filesize < 204800
}