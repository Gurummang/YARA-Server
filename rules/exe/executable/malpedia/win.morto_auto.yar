rule win_morto_auto {

    meta:
        atk_type = "win.morto."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.morto."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.morto"
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
        $sequence_0 = { 280c30 40 3b450c 72f4 8b4608 6a40 }
            // n = 6, score = 200
            //   280c30               | sub                 byte ptr [eax + esi], cl
            //   40                   | inc                 eax
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   72f4                 | jb                  0xfffffff6
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   6a40                 | push                0x40

        $sequence_1 = { 50 e8???????? 83c40c 8945e4 8d45cc }
            // n = 5, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8d45cc               | lea                 eax, [ebp - 0x34]

        $sequence_2 = { 03d0 8911 ffd2 5f 5e }
            // n = 5, score = 200
            //   03d0                 | add                 edx, eax
            //   8911                 | mov                 dword ptr [ecx], edx
            //   ffd2                 | call                edx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_3 = { 03f5 42 8a1e 46 }
            // n = 4, score = 200
            //   03f5                 | add                 esi, ebp
            //   42                   | inc                 edx
            //   8a1e                 | mov                 bl, byte ptr [esi]
            //   46                   | inc                 esi

        $sequence_4 = { ff35???????? c745ec04000000 c745fce8030000 ff15???????? }
            // n = 4, score = 200
            //   ff35????????         |                     
            //   c745ec04000000       | mov                 dword ptr [ebp - 0x14], 4
            //   c745fce8030000       | mov                 dword ptr [ebp - 4], 0x3e8
            //   ff15????????         |                     

        $sequence_5 = { 8bf0 c1ee08 83e601 8d3c56 }
            // n = 4, score = 200
            //   8bf0                 | mov                 esi, eax
            //   c1ee08               | shr                 esi, 8
            //   83e601               | and                 esi, 1
            //   8d3c56               | lea                 edi, [esi + edx*2]

        $sequence_6 = { 41 8d441201 8bd0 c1ea08 83e201 a87f 8d3c7a }
            // n = 7, score = 200
            //   41                   | inc                 ecx
            //   8d441201             | lea                 eax, [edx + edx + 1]
            //   8bd0                 | mov                 edx, eax
            //   c1ea08               | shr                 edx, 8
            //   83e201               | and                 edx, 1
            //   a87f                 | test                al, 0x7f
            //   8d3c7a               | lea                 edi, [edx + edi*2]

        $sequence_7 = { c745d0636c6965 c745d46e745c61 8945d8 c745dc44726f70 }
            // n = 4, score = 200
            //   c745d0636c6965       | mov                 dword ptr [ebp - 0x30], 0x65696c63
            //   c745d46e745c61       | mov                 dword ptr [ebp - 0x2c], 0x615c746e
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   c745dc44726f70       | mov                 dword ptr [ebp - 0x24], 0x706f7244

        $sequence_8 = { 6802000080 ff55e0 85c0 755f 8d45f8 50 }
            // n = 6, score = 200
            //   6802000080           | push                0x80000002
            //   ff55e0               | call                dword ptr [ebp - 0x20]
            //   85c0                 | test                eax, eax
            //   755f                 | jne                 0x61
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax

        $sequence_9 = { 894dfc 895508 eb03 8b75f4 b980000000 33c0 8dbdf0fdffff }
            // n = 7, score = 200
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   eb03                 | jmp                 5
            //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
            //   b980000000           | mov                 ecx, 0x80
            //   33c0                 | xor                 eax, eax
            //   8dbdf0fdffff         | lea                 edi, [ebp - 0x210]

    condition:
        7 of them and filesize < 49152
}