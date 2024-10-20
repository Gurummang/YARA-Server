rule win_hazy_load_auto {

    meta:
        atk_type = "win.hazy_load."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hazy_load."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hazy_load"
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
        $sequence_0 = { b904000000 4c8d05f5c50000 488d15aeb20000 e8???????? 488bf8 4885c0 740f }
            // n = 7, score = 100
            //   b904000000           | mov                 ebp, esp
            //   4c8d05f5c50000       | dec                 eax
            //   488d15aeb20000       | sub                 esp, 0x80
            //   e8????????           |                     
            //   488bf8               | dec                 eax
            //   4885c0               | xor                 eax, esp
            //   740f                 | dec                 eax

        $sequence_1 = { 48897c2408 488b15???????? 488d3dd16d0100 8bc2 b940000000 83e03f 2bc8 }
            // n = 7, score = 100
            //   48897c2408           | lea                 eax, [esp + 0x28]
            //   488b15????????       |                     
            //   488d3dd16d0100       | xor                 eax, eax
            //   8bc2                 | dec                 eax
            //   b940000000           | mov                 dword ptr [esp + 0x20], eax
            //   83e03f               | xor                 ebx, ebx
            //   2bc8                 | nop                 dword ptr [eax]

        $sequence_2 = { 488d0db8200100 4183e23f 4903e8 832700 498bf0 }
            // n = 5, score = 100
            //   488d0db8200100       | dec                 eax
            //   4183e23f             | lea                 edx, [0xaad8]
            //   4903e8               | dec                 esp
            //   832700               | lea                 eax, [0xaad5]
            //   498bf0               | dec                 eax

        $sequence_3 = { 488bf1 41bc02000000 4489742420 418bcc 448d4205 ff15???????? }
            // n = 6, score = 100
            //   488bf1               | xor                 al, al
            //   41bc02000000         | add                 edi, eax
            //   4489742420           | cmp                 edi, 0x10
            //   418bcc               | jl                  0xffffffee
            //   448d4205             | cmp                 edi, 0x10
            //   ff15????????         |                     

        $sequence_4 = { 4b87bcf750140200 33c0 488b5c2450 488b6c2458 488b742460 }
            // n = 5, score = 100
            //   4b87bcf750140200     | dec                 eax
            //   33c0                 | lea                 ecx, [0x12ced]
            //   488b5c2450           | dec                 eax
            //   488b6c2458           | add                 esp, 0x290
            //   488b742460           | pop                 ebp

        $sequence_5 = { 483b0d???????? 7417 488d0570630100 483bc8 740b 83791000 7505 }
            // n = 7, score = 100
            //   483b0d????????       |                     
            //   7417                 | dec                 eax
            //   488d0570630100       | cwde                
            //   483bc8               | dec                 eax
            //   740b                 | cmp                 eax, 0xe4
            //   83791000             | jae                 0x51
            //   7505                 | dec                 eax

        $sequence_6 = { 4883675000 488d05ade0ffff 83675800 488d4f28 }
            // n = 4, score = 100
            //   4883675000           | dec                 eax
            //   488d05ade0ffff       | arpl                bx, ax
            //   83675800             | dec                 eax
            //   488d4f28             | lea                 edx, [ebp + 4]

        $sequence_7 = { 488d15a96a0100 83e13f 488bc5 48c1f806 48c1e106 }
            // n = 5, score = 100
            //   488d15a96a0100       | mov                 ebp, eax
            //   83e13f               | dec                 esp
            //   488bc5               | lea                 ecx, [0xffffca7f]
            //   48c1f806             | inc                 esp
            //   48c1e106             | lea                 eax, [edx + 5]

        $sequence_8 = { 442bc3 4803d0 4533c9 488bce ff15???????? 85c0 0f8eacfeffff }
            // n = 7, score = 100
            //   442bc3               | lea                 ecx, [esp + 0x20]
            //   4803d0               | xor                 edx, edx
            //   4533c9               | dec                 eax
            //   488bce               | lea                 ecx, [esp + 0x130]
            //   ff15????????         |                     
            //   85c0                 | inc                 ecx
            //   0f8eacfeffff         | mov                 eax, 0x104

        $sequence_9 = { 488d0dc0210100 4183e23f 4903e8 832300 }
            // n = 4, score = 100
            //   488d0dc0210100       | mov                 eax, 5
            //   4183e23f             | mov                 dword ptr [ebp + 0x20], eax
            //   4903e8               | dec                 eax
            //   832300               | mov                 dword ptr [ebp - 1], eax

    condition:
        7 of them and filesize < 315392
}