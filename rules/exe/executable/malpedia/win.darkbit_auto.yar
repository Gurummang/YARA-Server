rule win_darkbit_auto {

    meta:
        atk_type = "win.darkbit."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.darkbit."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkbit"
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
        $sequence_0 = { e8???????? 48898424f0140000 48899c2498020000 488b0d???????? 48898c2478100000 488d05c1742500 90 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   48898424f0140000     | dec                 eax
            //   48899c2498020000     | mov                 dword ptr [eax + 8], ecx
            //   488b0d????????       |                     
            //   48898c2478100000     | jne                 0x561
            //   488d05c1742500       | dec                 eax
            //   90                   | mov                 ecx, dword ptr [esp + 0x21c8]

        $sequence_1 = { eb23 4889c7 488b8c24d0180000 e8???????? 488d7810 488b8424c8180000 6690 }
            // n = 7, score = 100
            //   eb23                 | neg                 eax
            //   4889c7               | dec                 ecx
            //   488b8c24d0180000     | cmp                 eax, 0x10
            //   e8????????           |                     
            //   488d7810             | jb                  0xb9c
            //   488b8424c8180000     | dec                 eax
            //   6690                 | mov                 esi, dword ptr [esi + 0x90]

        $sequence_2 = { e8???????? 4889842410010000 48899c2418070000 488b442460 48c7c3feffffff e8???????? 4889842470010000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4889842410010000     | mov                 edx, edi
            //   48899c2418070000     | dec                 esp
            //   488b442460           | or                  edi, eax
            //   48c7c3feffffff       | dec                 ecx
            //   e8????????           |                     
            //   4889842470010000     | not                 ecx

        $sequence_3 = { eb11 488d7818 488b8c24f0110000 e8???????? 488b8c24e8030000 48894810 833d????????00 }
            // n = 7, score = 100
            //   eb11                 | mov                 edx, ebx
            //   488d7818             | dec                 eax
            //   488b8c24f0110000     | mov                 ecx, dword ptr [ecx + 0xf8]
            //   e8????????           |                     
            //   488b8c24e8030000     | dec                 eax
            //   48894810             | mov                 eax, edx
            //   833d????????00       |                     

        $sequence_4 = { 833d????????00 7515 488b8c24a81e0000 488908 488905???????? 90 eb1c }
            // n = 7, score = 100
            //   833d????????00       |                     
            //   7515                 | dec                 eax
            //   488b8c24a81e0000     | mov                 ecx, dword ptr [esp + 0x2698]
            //   488908               | dec                 eax
            //   488905????????       |                     
            //   90                   | lea                 edi, [0x229363]
            //   eb1c                 | jmp                 0xb59

        $sequence_5 = { e8???????? 488b542440 48895008 833d????????00 750d 488b9424c0000000 488910 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b542440           | dec                 eax
            //   48895008             | mov                 ecx, dword ptr [esp + 0x2570]
            //   833d????????00       |                     
            //   750d                 | dec                 eax
            //   488b9424c0000000     | mov                 dword ptr [eax], ecx
            //   488910               | dec                 eax

        $sequence_6 = { e8???????? 4889842428080000 48899c2480110000 488b8424a0080000 48c7c3ffffffff 0f1f440000 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4889842428080000     | mov                 eax, edi
            //   48899c2480110000     | jmp                 0x32
            //   488b8424a0080000     | dec                 eax
            //   48c7c3ffffffff       | dec                 edi
            //   0f1f440000           | dec                 eax
            //   e8????????           |                     

        $sequence_7 = { e8???????? 488d8424d8000000 488b9c2408010000 90 e8???????? b801000000 eb21 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d8424d8000000     | mov                 dword ptr [eax + 0x10], ecx
            //   488b9c2408010000     | jne                 0x1a35
            //   90                   | dec                 eax
            //   e8????????           |                     
            //   b801000000           | mov                 ecx, dword ptr [esp + 0x15f8]
            //   eb21                 | dec                 eax

        $sequence_8 = { e8???????? 803d????????00 7431 488d1543fa1a00 488915???????? 833d????????00 7509 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   803d????????00       |                     
            //   7431                 | mov                 eax, dword ptr [esp + 0x340]
            //   488d1543fa1a00       | dec                 eax
            //   488915????????       |                     
            //   833d????????00       |                     
            //   7509                 | mov                 ebx, edx

        $sequence_9 = { ffd2 84c0 7556 488d0509aa3000 488b5c2430 488b4c2438 e8???????? }
            // n = 7, score = 100
            //   ffd2                 | dec                 esp
            //   84c0                 | mov                 eax, dword ptr [esp + 0xa0]
            //   7556                 | dec                 eax
            //   488d0509aa3000       | mov                 edi, dword ptr [esp + 0x2d8]
            //   488b5c2430           | dec                 esp
            //   488b4c2438           | mov                 eax, dword ptr [esp + 0xa8]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 11612160
}