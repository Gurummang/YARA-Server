rule win_iconic_stealer_auto {

    meta:
        atk_type = "win.iconic_stealer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.iconic_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iconic_stealer"
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
        $sequence_0 = { e9???????? 4c8b13 4c8d05e6c60300 488bc6 488bce 83e03f 48c1f906 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   4c8b13               | mov                 ecx, eax
            //   4c8d05e6c60300       | inc                 ecx
            //   488bc6               | mov                 eax, eax
            //   488bce               | and                 eax, 0xff00
            //   83e03f               | shl                 ecx, 0x10
            //   48c1f906             | inc                 esp

        $sequence_1 = { eb29 488d0c76 8d4601 898790000000 488b8788000000 c704c876000000 8954c804 }
            // n = 7, score = 100
            //   eb29                 | test                eax, eax
            //   488d0c76             | je                  0xbdd
            //   8d4601               | dec                 esp
            //   898790000000         | mov                 eax, eax
            //   488b8788000000       | inc                 esp
            //   c704c876000000       | mov                 dword ptr [eax + ecx*8 + 8], eax
            //   8954c804             | mov                 dword ptr [eax + ecx*8 + 0xc], edx

        $sequence_2 = { 894338 66897318 66894b3e 6644896316 6644894b3c 663bf1 0f85dc000000 }
            // n = 7, score = 100
            //   894338               | mov                 dword ptr [eax], ecx
            //   66897318             | inc                 ebp
            //   66894b3e             | movzx               eax, ah
            //   6644896316           | dec                 eax
            //   6644894b3c           | mov                 ecx, dword ptr [ebp - 0x20]
            //   663bf1               | dec                 eax
            //   0f85dc000000         | mov                 eax, dword ptr [ebp - 0x28]

        $sequence_3 = { e8???????? 4881c430020000 415f 415d 415c 5f 5e }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4881c430020000       | inc                 ecx
            //   415f                 | mov                 ebp, ecx
            //   415d                 | jmp                 0x438
            //   415c                 | inc                 esp
            //   5f                   | mov                 dword ptr [ecx], ecx
            //   5e                   | dec                 eax

        $sequence_4 = { 5f 5e 5d c3 40f6c504 7419 4c8bc7 }
            // n = 7, score = 100
            //   5f                   | mov                 eax, edi
            //   5e                   | sar                 eax, 1
            //   5d                   | dec                 esp
            //   c3                   | arpl                ax, dx
            //   40f6c504             | dec                 ebx
            //   7419                 | lea                 edx, [edx + edx*2]
            //   4c8bc7               | dec                 ebp

        $sequence_5 = { eb05 b901000000 894f28 4885db 741f 8b4f28 48895f10 }
            // n = 7, score = 100
            //   eb05                 | cmp                 byte ptr [ecx + 0x3f], ch
            //   b901000000           | jne                 0x6a2
            //   894f28               | dec                 eax
            //   4885db               | mov                 ecx, dword ptr [eax]
            //   741f                 | lea                 edx, [ebp + 4]
            //   8b4f28               | dec                 esp
            //   48895f10             | mov                 edi, eax

        $sequence_6 = { f2490f2ad5 488d4dc7 f20f5e15???????? 66490f7ed0 e8???????? e9???????? 448b44242c }
            // n = 7, score = 100
            //   f2490f2ad5           | mov                 dword ptr [esp + 0x34], esi
            //   488d4dc7             | dec                 eax
            //   f20f5e15????????     |                     
            //   66490f7ed0           | mov                 ecx, dword ptr [ebx + 0x70]
            //   e8????????           |                     
            //   e9????????           |                     
            //   448b44242c           | test                byte ptr [ecx + 0x34], 4

        $sequence_7 = { ffc7 4883c108 3bfa 7cf1 e9???????? 488b4b20 4885c9 }
            // n = 7, score = 100
            //   ffc7                 | dec                 eax
            //   4883c108             | mov                 ecx, dword ptr [esp + 0xa0]
            //   3bfa                 | dec                 eax
            //   7cf1                 | mov                 eax, dword ptr [esp + 0xa8]
            //   e9????????           |                     
            //   488b4b20             | dec                 eax
            //   4885c9               | test                eax, eax

        $sequence_8 = { e9???????? 488b75a8 4c8b442470 8b06 83c003 413b00 7e1f }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488b75a8             | cmp                 ecx, eax
            //   4c8b442470           | jne                 0x13cd
            //   8b06                 | test                ecx, ecx
            //   83c003               | jne                 0x13e6
            //   413b00               | test                ebx, ebx
            //   7e1f                 | js                  0x1421

        $sequence_9 = { c7430400000000 41ba1f000000 49bb1142082184104208 418b49f8 85c9 745b 8d4701 }
            // n = 7, score = 100
            //   c7430400000000       | inc                 ecx
            //   41ba1f000000         | cmp                 dword ptr [eax], ecx
            //   49bb1142082184104208     | inc    ecx
            //   418b49f8             | mov                 eax, dword ptr [edi + 0x7c]
            //   85c9                 | bt                  eax, edi
            //   745b                 | jb                  0xd43
            //   8d4701               | bts                 eax, edi

    condition:
        7 of them and filesize < 2401280
}