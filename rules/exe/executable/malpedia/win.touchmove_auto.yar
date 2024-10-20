rule win_touchmove_auto {

    meta:
        atk_type = "win.touchmove."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.touchmove."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.touchmove"
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
        $sequence_0 = { 41b800040000 488d8c2452010000 e8???????? 4c8d442448 488d152df90000 }
            // n = 5, score = 100
            //   41b800040000         | movdqa              xmmword ptr [ebp + 0x2220], xmm5
            //   488d8c2452010000     | mov                 byte ptr [ebp + 0x2232], 0
            //   e8????????           |                     
            //   4c8d442448           | dec                 eax
            //   488d152df90000       | lea                 ecx, [ebp + 0xa20]

        $sequence_1 = { 488d157af70000 488d8d90000000 e8???????? 4c8d8590000000 33d2 33c9 }
            // n = 6, score = 100
            //   488d157af70000       | lea                 ecx, [esp + 0x152]
            //   488d8d90000000       | mov                 word ptr [ebp + 0x4d90], si
            //   e8????????           |                     
            //   4c8d8590000000       | xor                 edx, edx
            //   33d2                 | inc                 ecx
            //   33c9                 | mov                 eax, 0x400

        $sequence_2 = { 7528 48833d????????00 741e 488d0d499f0000 e8???????? 85c0 }
            // n = 6, score = 100
            //   7528                 | mov                 eax, 0xe7
            //   48833d????????00     |                     
            //   741e                 | mov                 dword ptr [ebp + 0x1730], 0x70616e53
            //   488d0d499f0000       | mov                 dword ptr [ebp + 0x1734], 0x746f6873
            //   e8????????           |                     
            //   85c0                 | xor                 edx, edx

        $sequence_3 = { 41b8ee000000 488d8d92430000 e8???????? c6858044000000 33d2 41b8ff000000 488d8d81440000 }
            // n = 7, score = 100
            //   41b8ee000000         | lea                 edx, [0xe497]
            //   488d8d92430000       | dec                 eax
            //   e8????????           |                     
            //   c6858044000000       | sar                 eax, 5
            //   33d2                 | and                 ecx, 0x1f
            //   41b8ff000000         | dec                 eax
            //   488d8d81440000       | mov                 eax, dword ptr [edx + eax*8]

        $sequence_4 = { ff15???????? 488d442450 4889442420 458bce 4533c0 488d9580410000 48c7c102000080 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488d442450           | xor                 edx, edx
            //   4889442420           | movdqa              xmmword ptr [ebp + 0x1520], xmm5
            //   458bce               | inc                 ecx
            //   4533c0               | mov                 eax, 0xe6
            //   488d9580410000       | mov                 dword ptr [ebp + 0x1530], 0x72747441
            //   48c7c102000080       | mov                 dword ptr [ebp + 0x1534], 0x74756269

        $sequence_5 = { 0f8514010000 4c8d2d36cd0000 41b804010000 668935???????? 498bd5 ff15???????? 418d7c24e7 }
            // n = 7, score = 100
            //   0f8514010000         | lea                 ecx, [ebp + 0x4680]
            //   4c8d2d36cd0000       | dec                 esp
            //   41b804010000         | lea                 eax, [ebp + 0x4880]
            //   668935????????       |                     
            //   498bd5               | dec                 eax
            //   ff15????????         |                     
            //   418d7c24e7           | lea                 edx, [0xe178]

        $sequence_6 = { 48833d????????00 0f844d040000 48833d????????00 0f843f040000 }
            // n = 4, score = 100
            //   48833d????????00     |                     
            //   0f844d040000         | inc                 ecx
            //   48833d????????00     |                     
            //   0f843f040000         | mov                 ecx, 4

        $sequence_7 = { 833d????????00 7505 e8???????? 488d3d40e00000 41b804010000 }
            // n = 5, score = 100
            //   833d????????00       |                     
            //   7505                 | dec                 eax
            //   e8????????           |                     
            //   488d3d40e00000       | and                 dword ptr [esp + 0x30], 0
            //   41b804010000         | and                 dword ptr [esp + 0x28], 0

        $sequence_8 = { 488bfb 488bf3 48c1fe05 4c8d25bebd0000 83e71f 486bff58 }
            // n = 6, score = 100
            //   488bfb               | inc                 ecx
            //   488bf3               | mov                 eax, 0x98
            //   48c1fe05             | dec                 ecx
            //   4c8d25bebd0000       | mov                 esi, ecx
            //   83e71f               | dec                 ebp
            //   486bff58             | mov                 ebp, esi

        $sequence_9 = { 8bc8 e8???????? ebc9 488bcb 488bc3 488d1597e40000 48c1f805 }
            // n = 7, score = 100
            //   8bc8                 | cmp                 dword ptr [edx], 0
            //   e8????????           |                     
            //   ebc9                 | jne                 0x2c8
            //   488bcb               | dec                 eax
            //   488bc3               | lea                 eax, [0x100f4]
            //   488d1597e40000       | dec                 esp
            //   48c1f805             | cmp                 edx, eax

    condition:
        7 of them and filesize < 224256
}