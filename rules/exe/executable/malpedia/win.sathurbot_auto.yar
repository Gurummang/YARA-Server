rule win_sathurbot_auto {

    meta:
        atk_type = "win.sathurbot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sathurbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sathurbot"
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
        $sequence_0 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b86b2c1f0a b9b2fd990f }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b86b2c1f0a           | mov                 eax, 0xa1f2c6b
            //   b9b2fd990f           | mov                 ecx, 0xf99fdb2

        $sequence_1 = { b94d1e0277 0f45c1 e9???????? 3ddc03f324 0f8582f1ffff a1???????? 8d48ff }
            // n = 7, score = 100
            //   b94d1e0277           | mov                 ecx, 0x77021e4d
            //   0f45c1               | cmovne              eax, ecx
            //   e9????????           |                     
            //   3ddc03f324           | cmp                 eax, 0x24f303dc
            //   0f8582f1ffff         | jne                 0xfffff188
            //   a1????????           |                     
            //   8d48ff               | lea                 ecx, [eax - 1]

        $sequence_2 = { e9???????? 81ff6e65f902 7f1b 81ffded97800 ba96b0469a 0f8548e7ffff bfadab28bf }
            // n = 7, score = 100
            //   e9????????           |                     
            //   81ff6e65f902         | cmp                 edi, 0x2f9656e
            //   7f1b                 | jg                  0x1d
            //   81ffded97800         | cmp                 edi, 0x78d9de
            //   ba96b0469a           | mov                 edx, 0x9a46b096
            //   0f8548e7ffff         | jne                 0xffffe74e
            //   bfadab28bf           | mov                 edi, 0xbf28abad

        $sequence_3 = { e9???????? b817aff9fc e9???????? 3dcf25ea47 0f85eef0ffff a1???????? 8d48ff }
            // n = 7, score = 100
            //   e9????????           |                     
            //   b817aff9fc           | mov                 eax, 0xfcf9af17
            //   e9????????           |                     
            //   3dcf25ea47           | cmp                 eax, 0x47ea25cf
            //   0f85eef0ffff         | jne                 0xfffff0f4
            //   a1????????           |                     
            //   8d48ff               | lea                 ecx, [eax - 1]

        $sequence_4 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b8d3b4c9a9 b9c79b14fb }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b8d3b4c9a9           | mov                 eax, 0xa9c9b4d3
            //   b9c79b14fb           | mov                 ecx, 0xfb149bc7

        $sequence_5 = { c744240400000000 89f1 e8???????? 83ec0c bafb0541ae b828f7da39 eb8f }
            // n = 7, score = 100
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   89f1                 | mov                 ecx, esi
            //   e8????????           |                     
            //   83ec0c               | sub                 esp, 0xc
            //   bafb0541ae           | mov                 edx, 0xae4105fb
            //   b828f7da39           | mov                 eax, 0x39daf728
            //   eb8f                 | jmp                 0xffffff91

        $sequence_6 = { b994a742ce 0f45c1 e9???????? 3d98320e47 0f8561fcffff 8a45ea 8a4deb }
            // n = 7, score = 100
            //   b994a742ce           | mov                 ecx, 0xce42a794
            //   0f45c1               | cmovne              eax, ecx
            //   e9????????           |                     
            //   3d98320e47           | cmp                 eax, 0x470e3298
            //   0f8561fcffff         | jne                 0xfffffc67
            //   8a45ea               | mov                 al, byte ptr [ebp - 0x16]
            //   8a4deb               | mov                 cl, byte ptr [ebp - 0x15]

        $sequence_7 = { f6c201 ba67157693 b85ee72ce5 0f45d0 e9???????? 3d4c9cd69e 89c2 }
            // n = 7, score = 100
            //   f6c201               | test                dl, 1
            //   ba67157693           | mov                 edx, 0x93761567
            //   b85ee72ce5           | mov                 eax, 0xe52ce75e
            //   0f45d0               | cmovne              edx, eax
            //   e9????????           |                     
            //   3d4c9cd69e           | cmp                 eax, 0x9ed69c4c
            //   89c2                 | mov                 edx, eax

        $sequence_8 = { e8???????? 83ec0c 8b45f0 8945d8 894610 89f1 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83ec0c               | sub                 esp, 0xc
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   89f1                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_9 = { bf51a32250 81fa39ccdcb8 74d7 ebfe 8b4304 83ec04 890424 }
            // n = 7, score = 100
            //   bf51a32250           | mov                 edi, 0x5022a351
            //   81fa39ccdcb8         | cmp                 edx, 0xb8dccc39
            //   74d7                 | je                  0xffffffd9
            //   ebfe                 | jmp                 0
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   83ec04               | sub                 esp, 4
            //   890424               | mov                 dword ptr [esp], eax

    condition:
        7 of them and filesize < 2727936
}