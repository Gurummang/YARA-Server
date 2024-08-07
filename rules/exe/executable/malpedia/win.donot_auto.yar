rule win_donot_auto {

    meta:
        atk_type = "win.donot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.donot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.donot"
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
        $sequence_0 = { 8b04c580b80310 5d c3 33c0 }
            // n = 4, score = 100
            //   8b04c580b80310       | mov                 eax, dword ptr [eax*8 + 0x1003b880]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { c7461400000000 0f1106 f30f7e45e4 660fd64610 c745e400000000 c745e80f000000 85d2 }
            // n = 7, score = 100
            //   c7461400000000       | mov                 dword ptr [esi + 0x14], 0
            //   0f1106               | movups              xmmword ptr [esi], xmm0
            //   f30f7e45e4           | movq                xmm0, qword ptr [ebp - 0x1c]
            //   660fd64610           | movq                qword ptr [esi + 0x10], xmm0
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745e80f000000       | mov                 dword ptr [ebp - 0x18], 0xf
            //   85d2                 | test                edx, edx

        $sequence_2 = { 03d3 d1fa 8d4102 894738 8b4710 8918 8b4720 }
            // n = 7, score = 100
            //   03d3                 | add                 edx, ebx
            //   d1fa                 | sar                 edx, 1
            //   8d4102               | lea                 eax, [ecx + 2]
            //   894738               | mov                 dword ptr [edi + 0x38], eax
            //   8b4710               | mov                 eax, dword ptr [edi + 0x10]
            //   8918                 | mov                 dword ptr [eax], ebx
            //   8b4720               | mov                 eax, dword ptr [edi + 0x20]

        $sequence_3 = { e8???????? 8b15???????? b910000000 2bd6 8a0432 8d7601 3046ff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b15????????         |                     
            //   b910000000           | mov                 ecx, 0x10
            //   2bd6                 | sub                 edx, esi
            //   8a0432               | mov                 al, byte ptr [edx + esi]
            //   8d7601               | lea                 esi, [esi + 1]
            //   3046ff               | xor                 byte ptr [esi - 1], al

        $sequence_4 = { 7361 8bc6 8bde 83e03f c1fb06 6bc838 8b049d187b0410 }
            // n = 7, score = 100
            //   7361                 | jae                 0x63
            //   8bc6                 | mov                 eax, esi
            //   8bde                 | mov                 ebx, esi
            //   83e03f               | and                 eax, 0x3f
            //   c1fb06               | sar                 ebx, 6
            //   6bc838               | imul                ecx, eax, 0x38
            //   8b049d187b0410       | mov                 eax, dword ptr [ebx*4 + 0x10047b18]

        $sequence_5 = { c645fc02 8d4dbc e8???????? 8bf8 83c404 3bf7 7465 }
            // n = 7, score = 100
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4
            //   3bf7                 | cmp                 esi, edi
            //   7465                 | je                  0x67

        $sequence_6 = { 0f438540ffffff 50 ff15???????? c645fc1b 8b559c 83fa10 722c }
            // n = 7, score = 100
            //   0f438540ffffff       | cmovae              eax, dword ptr [ebp - 0xc0]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c645fc1b             | mov                 byte ptr [ebp - 4], 0x1b
            //   8b559c               | mov                 edx, dword ptr [ebp - 0x64]
            //   83fa10               | cmp                 edx, 0x10
            //   722c                 | jb                  0x2e

        $sequence_7 = { c6861002000000 8b8e0c020000 83f910 722f 8b86f8010000 41 81f900100000 }
            // n = 7, score = 100
            //   c6861002000000       | mov                 byte ptr [esi + 0x210], 0
            //   8b8e0c020000         | mov                 ecx, dword ptr [esi + 0x20c]
            //   83f910               | cmp                 ecx, 0x10
            //   722f                 | jb                  0x31
            //   8b86f8010000         | mov                 eax, dword ptr [esi + 0x1f8]
            //   41                   | inc                 ecx
            //   81f900100000         | cmp                 ecx, 0x1000

        $sequence_8 = { c685bcedffff00 8d5101 8a01 41 84c0 75f9 }
            // n = 6, score = 100
            //   c685bcedffff00       | mov                 byte ptr [ebp - 0x1244], 0
            //   8d5101               | lea                 edx, [ecx + 1]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb

        $sequence_9 = { c6863801000000 8b8e34010000 83f910 722f 8b8620010000 41 81f900100000 }
            // n = 7, score = 100
            //   c6863801000000       | mov                 byte ptr [esi + 0x138], 0
            //   8b8e34010000         | mov                 ecx, dword ptr [esi + 0x134]
            //   83f910               | cmp                 ecx, 0x10
            //   722f                 | jb                  0x31
            //   8b8620010000         | mov                 eax, dword ptr [esi + 0x120]
            //   41                   | inc                 ecx
            //   81f900100000         | cmp                 ecx, 0x1000

    condition:
        7 of them and filesize < 626688
}