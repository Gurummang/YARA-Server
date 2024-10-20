rule win_salgorea_auto {

    meta:
        atk_type = "win.salgorea."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.salgorea."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.salgorea"
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
        $sequence_0 = { 8b5c240c 53 9d 8b5c2404 }
            // n = 4, score = 300
            //   8b5c240c             | mov                 ebx, dword ptr [esp + 0xc]
            //   53                   | push                ebx
            //   9d                   | popfd               
            //   8b5c2404             | mov                 ebx, dword ptr [esp + 4]

        $sequence_1 = { 51 66b9b469 66f7f1 f7da }
            // n = 4, score = 300
            //   51                   | push                ecx
            //   66b9b469             | mov                 cx, 0x69b4
            //   66f7f1               | div                 cx
            //   f7da                 | neg                 edx

        $sequence_2 = { 51 6698 f7db 33d2 b889510000 b98c0b0000 }
            // n = 6, score = 300
            //   51                   | push                ecx
            //   6698                 | cbw                 
            //   f7db                 | neg                 ebx
            //   33d2                 | xor                 edx, edx
            //   b889510000           | mov                 eax, 0x5189
            //   b98c0b0000           | mov                 ecx, 0xb8c

        $sequence_3 = { 66c1e303 f6d1 f8 6633d2 66b8b96a 66b9ada1 66f7f1 }
            // n = 7, score = 300
            //   66c1e303             | shl                 bx, 3
            //   f6d1                 | not                 cl
            //   f8                   | clc                 
            //   6633d2               | xor                 dx, dx
            //   66b8b96a             | mov                 ax, 0x6ab9
            //   66b9ada1             | mov                 cx, 0xa1ad
            //   66f7f1               | div                 cx

        $sequence_4 = { 66c1e306 80eb38 80e6ee f8 f6d1 52 40 }
            // n = 7, score = 300
            //   66c1e306             | shl                 bx, 6
            //   80eb38               | sub                 bl, 0x38
            //   80e6ee               | and                 dh, 0xee
            //   f8                   | clc                 
            //   f6d1                 | not                 cl
            //   52                   | push                edx
            //   40                   | inc                 eax

        $sequence_5 = { 8b5c2404 f8 99 8b1424 f5 66f7d8 8b442410 }
            // n = 7, score = 300
            //   8b5c2404             | mov                 ebx, dword ptr [esp + 4]
            //   f8                   | clc                 
            //   99                   | cdq                 
            //   8b1424               | mov                 edx, dword ptr [esp]
            //   f5                   | cmc                 
            //   66f7d8               | neg                 ax
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]

        $sequence_6 = { 66c1e804 8b44240c 0fbafa00 0fbcd2 }
            // n = 4, score = 300
            //   66c1e804             | shr                 ax, 4
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   0fbafa00             | btc                 edx, 0
            //   0fbcd2               | bsf                 edx, edx

        $sequence_7 = { 8b5c240c 53 d50a 48 d40a 22c9 }
            // n = 6, score = 300
            //   8b5c240c             | mov                 ebx, dword ptr [esp + 0xc]
            //   53                   | push                ebx
            //   d50a                 | aad                 
            //   48                   | dec                 eax
            //   d40a                 | aam                 
            //   22c9                 | and                 cl, cl

        $sequence_8 = { a1???????? 8945cc 8d45cc 3930 }
            // n = 4, score = 200
            //   a1????????           |                     
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   3930                 | cmp                 dword ptr [eax], esi

        $sequence_9 = { 8d87d8010000 50 8d83d8010000 50 }
            // n = 4, score = 100
            //   8d87d8010000         | lea                 eax, [edi + 0x1d8]
            //   50                   | push                eax
            //   8d83d8010000         | lea                 eax, [ebx + 0x1d8]
            //   50                   | push                eax

        $sequence_10 = { 8d8850040000 8d984c040000 8b4510 8b00 }
            // n = 4, score = 100
            //   8d8850040000         | lea                 ecx, [eax + 0x450]
            //   8d984c040000         | lea                 ebx, [eax + 0x44c]
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_11 = { 8d885c040000 8d9858040000 e9???????? 8b7508 }
            // n = 4, score = 100
            //   8d885c040000         | lea                 ecx, [eax + 0x45c]
            //   8d9858040000         | lea                 ebx, [eax + 0x458]
            //   e9????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_12 = { 8d87d8010000 50 e8???????? 59 59 85c0 }
            // n = 6, score = 100
            //   8d87d8010000         | lea                 eax, [edi + 0x1d8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_13 = { 8d87d8010000 50 8d83b0020000 50 e8???????? 59 }
            // n = 6, score = 100
            //   8d87d8010000         | lea                 eax, [edi + 0x1d8]
            //   50                   | push                eax
            //   8d83b0020000         | lea                 eax, [ebx + 0x2b0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_14 = { 8d8860010000 0fb701 a801 740a }
            // n = 4, score = 100
            //   8d8860010000         | lea                 ecx, [eax + 0x160]
            //   0fb701               | movzx               eax, word ptr [ecx]
            //   a801                 | test                al, 1
            //   740a                 | je                  0xc

        $sequence_15 = { 8d8840010000 8d9044010000 56 8b750c }
            // n = 4, score = 100
            //   8d8840010000         | lea                 ecx, [eax + 0x140]
            //   8d9044010000         | lea                 edx, [eax + 0x144]
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 2007040
}