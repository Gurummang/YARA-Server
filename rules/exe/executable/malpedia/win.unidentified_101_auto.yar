rule win_unidentified_101_auto {

    meta:
        atk_type = "win.unidentified_101."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.unidentified_101."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_101"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { c70016000000 e8???????? 83c8ff e9???????? 498bc4 488d0ddb070100 83e03f }
            // n = 7, score = 100
            //   c70016000000         | and                 ecx, 0xf
            //   e8????????           |                     
            //   83c8ff               | dec                 edx
            //   e9????????           |                     
            //   498bc4               | movsx               eax, byte ptr [ecx + eax + 0x1e400]
            //   488d0ddb070100       | mov                 eax, dword ptr [edx - 4]
            //   83e03f               | shr                 eax, cl

        $sequence_1 = { 6689842404010000 b865000000 6689842406010000 33c0 6689842408010000 }
            // n = 5, score = 100
            //   6689842404010000     | lea                 ecx, [0x21d51]
            //   b865000000           | dec                 eax
            //   6689842406010000     | lea                 eax, [0x21d55]
            //   33c0                 | ret                 
            //   6689842408010000     | dec                 eax

        $sequence_2 = { 33c0 b968000000 f3aa 488d842400010000 4889442448 488d842430020000 4889442440 }
            // n = 7, score = 100
            //   33c0                 | jmp                 0x1c09
            //   b968000000           | dec                 eax
            //   f3aa                 | mov                 dword ptr [esp + 0x20], eax
            //   488d842400010000     | dec                 eax
            //   4889442448           | cmp                 dword ptr [esp + 0x20], 0
            //   488d842430020000     | je                  0x1c0d
            //   4889442440           | jmp                 0x1c1a

        $sequence_3 = { 4889742410 57 4883ec20 418bf0 4c8d0debb40000 8bda 4c8d05dab40000 }
            // n = 7, score = 100
            //   4889742410           | inc                 ecx
            //   57                   | push                esi
            //   4883ec20             | inc                 ecx
            //   418bf0               | push                edi
            //   4c8d0debb40000       | dec                 eax
            //   8bda                 | sub                 esp, 0x20
            //   4c8d05dab40000       | inc                 esp

        $sequence_4 = { c744243000000000 4c8d4c2430 4c8b442440 8b542468 488b4c2460 }
            // n = 5, score = 100
            //   c744243000000000     | mov                 word ptr [esp + 0x104], ax
            //   4c8d4c2430           | mov                 eax, 0x65
            //   4c8b442440           | mov                 eax, 0x65
            //   8b542468             | mov                 word ptr [esp + 0x106], ax
            //   488b4c2460           | xor                 eax, eax

        $sequence_5 = { c68424e900000065 c68424ea00000057 c68424eb00000000 c644243052 c644243165 c644243261 c644243364 }
            // n = 7, score = 100
            //   c68424e900000065     | imul                eax, eax, 0
            //   c68424ea00000057     | movzx               eax, word ptr [esp + eax + 0xd0]
            //   c68424eb00000000     | cmp                 eax, 0x63
            //   c644243052           | mov                 dword ptr [ebp + 0x340], eax
            //   c644243165           | dec                 eax
            //   c644243261           | lea                 ecx, [0xfffe82d4]
            //   c644243364           | dec                 eax

        $sequence_6 = { 428a8c1910e40100 4c2bc0 418b40fc 4d894108 d3e8 41894120 }
            // n = 6, score = 100
            //   428a8c1910e40100     | mov                 byte ptr [esp + 0x80], 0x43
            //   4c2bc0               | mov                 byte ptr [esp + 0x81], 0x72
            //   418b40fc             | mov                 byte ptr [esp + 0x2ac], 0x65
            //   4d894108             | mov                 byte ptr [esp + 0x2ad], 0x61
            //   d3e8                 | mov                 byte ptr [esp + 0x2ae], 0x74
            //   41894120             | mov                 byte ptr [esp + 0x2af], 0x65

        $sequence_7 = { 48c744242000000000 4c8d8c24c8000000 448b442450 488b542458 488b4c2470 ff15???????? }
            // n = 6, score = 100
            //   48c744242000000000     | dec    eax
            //   4c8d8c24c8000000     | lea                 eax, [ebp - 0x18]
            //   448b442450           | dec                 eax
            //   488b542458           | mov                 dword ptr [ebp - 0x18], ecx
            //   488b4c2470           | dec                 eax
            //   ff15????????         |                     

        $sequence_8 = { 41b804010000 488d942400030000 33c9 ff15???????? c744245801000000 e8???????? 833d????????01 }
            // n = 7, score = 100
            //   41b804010000         | dec                 eax
            //   488d942400030000     | lea                 eax, [esp + 0x1f0]
            //   33c9                 | dec                 eax
            //   ff15????????         |                     
            //   c744245801000000     | mov                 edi, eax
            //   e8????????           |                     
            //   833d????????01       |                     

        $sequence_9 = { 7528 48833d????????00 741e 488d0dd8450100 e8???????? 85c0 740e }
            // n = 7, score = 100
            //   7528                 | lea                 edx, [edx + edx*8]
            //   48833d????????00     |                     
            //   741e                 | dec                 esp
            //   488d0dd8450100       | mov                 esi, dword ptr [eax + edx*8 + 0x28]
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   740e                 | lea                 ecx, [0x10c6c]

    condition:
        7 of them and filesize < 402432
}