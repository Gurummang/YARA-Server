rule win_bravonc_auto {

    meta:
        atk_type = "win.bravonc."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.bravonc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bravonc"
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
        $sequence_0 = { 0f8c05040000 8b06 3b7804 0f8dfa030000 395e04 7407 50 }
            // n = 7, score = 100
            //   0f8c05040000         | jl                  0x40b
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   3b7804               | cmp                 edi, dword ptr [eax + 4]
            //   0f8dfa030000         | jge                 0x400
            //   395e04               | cmp                 dword ptr [esi + 4], ebx
            //   7407                 | je                  9
            //   50                   | push                eax

        $sequence_1 = { 5b c3 55 8bec 53 33db 395d0c }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   395d0c               | cmp                 dword ptr [ebp + 0xc], ebx

        $sequence_2 = { 57 ff75ec 334dec 030a 034df0 8d8401d6c162ca 8945f0 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   334dec               | xor                 ecx, dword ptr [ebp - 0x14]
            //   030a                 | add                 ecx, dword ptr [edx]
            //   034df0               | add                 ecx, dword ptr [ebp - 0x10]
            //   8d8401d6c162ca       | lea                 eax, [ecx + eax - 0x359d3e2a]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_3 = { 8907 8b45f4 2bfb 59 59 8907 8b45fc }
            // n = 7, score = 100
            //   8907                 | mov                 dword ptr [edi], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   2bfb                 | sub                 edi, ebx
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8907                 | mov                 dword ptr [edi], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_4 = { 83c430 8bce 53 56 e8???????? 5f 5e }
            // n = 7, score = 100
            //   83c430               | add                 esp, 0x30
            //   8bce                 | mov                 ecx, esi
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_5 = { e8???????? 8b0e 030f c1e104 2bc1 eb08 8d4de0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   030f                 | add                 ecx, dword ptr [edi]
            //   c1e104               | shl                 ecx, 4
            //   2bc1                 | sub                 eax, ecx
            //   eb08                 | jmp                 0xa
            //   8d4de0               | lea                 ecx, [ebp - 0x20]

        $sequence_6 = { ff75f0 e8???????? 8b4df8 83c440 334dec 57 }
            // n = 6, score = 100
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c440               | add                 esp, 0x40
            //   334dec               | xor                 ecx, dword ptr [ebp - 0x14]
            //   57                   | push                edi

        $sequence_7 = { 335dfc 3175fc 83c118 ff4df0 8bf2 8b55fc 8955f8 }
            // n = 7, score = 100
            //   335dfc               | xor                 ebx, dword ptr [ebp - 4]
            //   3175fc               | xor                 dword ptr [ebp - 4], esi
            //   83c118               | add                 ecx, 0x18
            //   ff4df0               | dec                 dword ptr [ebp - 0x10]
            //   8bf2                 | mov                 esi, edx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8955f8               | mov                 dword ptr [ebp - 8], edx

        $sequence_8 = { 83450c08 ebd2 d36d08 8b0c8590b24000 234d08 014df0 8bc8 }
            // n = 7, score = 100
            //   83450c08             | add                 dword ptr [ebp + 0xc], 8
            //   ebd2                 | jmp                 0xffffffd4
            //   d36d08               | shr                 dword ptr [ebp + 8], cl
            //   8b0c8590b24000       | mov                 ecx, dword ptr [eax*4 + 0x40b290]
            //   234d08               | and                 ecx, dword ptr [ebp + 8]
            //   014df0               | add                 dword ptr [ebp - 0x10], ecx
            //   8bc8                 | mov                 ecx, eax

        $sequence_9 = { 03f3 2bfb 03f3 890f }
            // n = 4, score = 100
            //   03f3                 | add                 esi, ebx
            //   2bfb                 | sub                 edi, ebx
            //   03f3                 | add                 esi, ebx
            //   890f                 | mov                 dword ptr [edi], ecx

    condition:
        7 of them and filesize < 131072
}