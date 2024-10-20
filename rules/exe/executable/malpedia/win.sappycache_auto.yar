rule win_sappycache_auto {

    meta:
        atk_type = "win.sappycache."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sappycache."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sappycache"
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
        $sequence_0 = { 448bcf 895c2428 33d2 33c9 4889442420 488bf0 ff15???????? }
            // n = 7, score = 200
            //   448bcf               | jmp                 0x34f
            //   895c2428             | jmp                 0x2dc
            //   33d2                 | dec                 eax
            //   33c9                 | ror                 edi, cl
            //   4889442420           | dec                 eax
            //   488bf0               | lea                 ecx, [0xffffba5a]
            //   ff15????????         |                     

        $sequence_1 = { ff15???????? 85c0 7428 488bcd 488d1545f80000 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   85c0                 | lea                 ecx, [0x12b41]
            //   7428                 | dec                 eax
            //   488bcd               | lea                 ecx, [0x1614c]
            //   488d1545f80000       | dec                 eax

        $sequence_2 = { 488b8188000000 488d0d16fa0000 4883c018 7452 8bd7 0f1000 }
            // n = 6, score = 200
            //   488b8188000000       | movups              xmm0, xmmword ptr [ebx]
            //   488d0d16fa0000       | dec                 eax
            //   4883c018             | lea                 ebx, [ebx + 0x80]
            //   7452                 | movups              xmmword ptr [eax - 0x80], xmm0
            //   8bd7                 | movups              xmm1, xmmword ptr [ebx - 0x70]
            //   0f1000               | nop                 dword ptr [eax]

        $sequence_3 = { ff15???????? 41b904000000 c7452060ea0000 4c8d4520 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   41b904000000         | dec                 esp
            //   c7452060ea0000       | lea                 eax, [esp + 0x24]
            //   4c8d4520             | dec                 eax

        $sequence_4 = { 4c8d0dd6860000 c5f35cca c4c173590cc1 4c8d0da5760000 c5f359c1 }
            // n = 5, score = 200
            //   4c8d0dd6860000       | xor                 ecx, ecx
            //   c5f35cca             | dec                 eax
            //   c4c173590cc1         | add                 eax, 0x24
            //   4c8d0da5760000       | mov                 dword ptr [eax], edi
            //   c5f359c1             | dec                 eax

        $sequence_5 = { 49ffc0 47382c04 75f7 488d157c1f0100 }
            // n = 4, score = 200
            //   49ffc0               | or                  edi, 0xffffffff
            //   47382c04             | dec                 eax
            //   75f7                 | lea                 eax, [ebp + 0x240]
            //   488d157c1f0100       | dec                 eax

        $sequence_6 = { 4c89742430 448bcf 895c2428 33d2 33c9 4889442420 }
            // n = 6, score = 200
            //   4c89742430           | xor                 eax, eax
            //   448bcf               | xor                 ecx, ecx
            //   895c2428             | inc                 ecx
            //   33d2                 | lea                 edx, [ecx + 0x5f]
            //   33c9                 | inc                 ecx
            //   4889442420           | mov                 ecx, 4

        $sequence_7 = { f20f1000 8b7808 e9???????? 488d05eed70000 4a8b0ce8 42f644313880 744d }
            // n = 7, score = 200
            //   f20f1000             | lea                 eax, [ebp + 0x24]
            //   8b7808               | dec                 eax
            //   e9????????           |                     
            //   488d05eed70000       | mov                 dword ptr [esp + 0x28], eax
            //   4a8b0ce8             | dec                 eax
            //   42f644313880         | lea                 edx, [0x11f86]
            //   744d                 | dec                 eax

        $sequence_8 = { 4c8d0d136d0000 8bf9 488d15ba4d0000 b906000000 4c8d05f66c0000 e8???????? }
            // n = 6, score = 200
            //   4c8d0d136d0000       | dec                 eax
            //   8bf9                 | add                 edx, eax
            //   488d15ba4d0000       | dec                 eax
            //   b906000000           | mov                 dword ptr [esp + 0x98], ebp
            //   4c8d05f66c0000       | inc                 ecx
            //   e8????????           |                     

        $sequence_9 = { 4180e003 80e30f 41c0e004 440ac0 }
            // n = 4, score = 200
            //   4180e003             | lea                 ecx, [ebx + ebx*4]
            //   80e30f               | xor                 ebx, ebx
            //   41c0e004             | dec                 eax
            //   440ac0               | lea                 edi, [0xf6ad]

    condition:
        7 of them and filesize < 262144
}