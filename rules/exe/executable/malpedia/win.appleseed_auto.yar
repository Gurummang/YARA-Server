rule win_appleseed_auto {

    meta:
        atk_type = "win.appleseed."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.appleseed."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.appleseed"
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
        $sequence_0 = { 448bc6 442bc0 488b442450 488d0d65d30100 488b0cc1 4c8d4c244c 488d9520060000 }
            // n = 7, score = 100
            //   448bc6               | mov                 edx, dword ptr [eax]
            //   442bc0               | dec                 eax
            //   488b442450           | mov                 dword ptr [ebp + 0x70], 0xf
            //   488d0d65d30100       | xor                 esi, esi
            //   488b0cc1             | dec                 eax
            //   4c8d4c244c           | mov                 dword ptr [ebp + 0x68], esi
            //   488d9520060000       | dec                 eax

        $sequence_1 = { 4c89b590000000 c6858000000000 4883bde000000010 720c 488b8dc8000000 e8???????? 8bc7 }
            // n = 7, score = 100
            //   4c89b590000000       | lea                 ecx, [ebp - 0x48]
            //   c6858000000000       | je                  0x2de5
            //   4883bde000000010     | dec                 eax
            //   720c                 | lea                 edx, [0x21c03]
            //   488b8dc8000000       | nop                 
            //   e8????????           |                     
            //   8bc7                 | dec                 eax

        $sequence_2 = { 90 488d4db8 e8???????? 48833d????????00 0f84b10c0000 }
            // n = 5, score = 100
            //   90                   | dec                 eax
            //   488d4db8             | mov                 dword ptr [esp + 0x68], esi
            //   e8????????           |                     
            //   48833d????????00     |                     
            //   0f84b10c0000         | inc                 eax

        $sequence_3 = { 488bcb ff15???????? ff15???????? 33ff 8bf0 0f1f8000000000 ff15???????? }
            // n = 7, score = 100
            //   488bcb               | dec                 eax
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   33ff                 | mov                 dword ptr [esp + 0x68], 0xf
            //   8bf0                 | dec                 eax
            //   0f1f8000000000       | mov                 dword ptr [esp + 0x60], edi
            //   ff15????????         |                     

        $sequence_4 = { 90 488d4db8 e8???????? 48833d????????00 0f84c0040000 488d157e170200 488d4db8 }
            // n = 7, score = 100
            //   90                   | lea                 ecx, [edx + 0x140]
            //   488d4db8             | dec                 eax
            //   e8????????           |                     
            //   48833d????????00     |                     
            //   0f84c0040000         | mov                 ecx, dword ptr [edx + 0x40]
            //   488d157e170200       | dec                 eax
            //   488d4db8             | mov                 ecx, dword ptr [edx + 0x40]

        $sequence_5 = { 488bce ff15???????? 4885c0 7411 83caff 488bc8 }
            // n = 6, score = 100
            //   488bce               | mov                 eax, dword ptr [esi]
            //   ff15????????         |                     
            //   4885c0               | jb                  0xef
            //   7411                 | dec                 eax
            //   83caff               | mov                 ecx, dword ptr [ebp - 1]
            //   488bc8               | nop                 

        $sequence_6 = { e9???????? 488d8af0000000 e9???????? 488b8a60000000 e9???????? 488d8a10010000 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488d8af0000000       | mov                 dword ptr [esp + 0x30], ebp
            //   e9????????           |                     
            //   488b8a60000000       | inc                 ecx
            //   e9????????           |                     
            //   488d8a10010000       | mov                 esi, ebp
            //   e9????????           |                     

        $sequence_7 = { 0f8490000000 85db 0f8488000000 41880f 4b8b84e900670300 4183caff 4103da }
            // n = 7, score = 100
            //   0f8490000000         | mov                 dword ptr [ebp - 0x70], 0xf
            //   85db                 | dec                 eax
            //   0f8488000000         | mov                 dword ptr [ebp - 0x78], esi
            //   41880f               | mov                 byte ptr [esp + 0x78], 0
            //   4b8b84e900670300     | dec                 eax
            //   4183caff             | cmp                 dword ptr [esp + 0x70], 0x10
            //   4103da               | dec                 eax

        $sequence_8 = { 48ffc7 803c3a00 75f7 488d4c2450 4c8bc7 e8???????? 488d4c2450 }
            // n = 7, score = 100
            //   48ffc7               | dec                 eax
            //   803c3a00             | lea                 ecx, [0xdee3]
            //   75f7                 | mov                 dword ptr [esp + 0x30], ebx
            //   488d4c2450           | dec                 eax
            //   4c8bc7               | lea                 edx, [0xdeba]
            //   e8????????           |                     
            //   488d4c2450           | test                ecx, ecx

        $sequence_9 = { 48895dc8 c645b800 41b838000000 488d15b81d0200 488d4db8 e8???????? 90 }
            // n = 7, score = 100
            //   48895dc8             | lea                 ecx, [ebp - 0x49]
            //   c645b800             | nop                 
            //   41b838000000         | dec                 eax
            //   488d15b81d0200       | cmp                 dword ptr [ebx + 0x18], 0x10
            //   488d4db8             | jb                  0x5ce
            //   e8????????           |                     
            //   90                   | dec                 eax

    condition:
        7 of them and filesize < 497664
}