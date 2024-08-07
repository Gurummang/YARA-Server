rule win_sinowal_auto {

    meta:
        atk_type = "win.sinowal."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sinowal."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sinowal"
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
        $sequence_0 = { 8d95bcfdffff 52 e8???????? 83c40c c745f000000000 }
            // n = 5, score = 200
            //   8d95bcfdffff         | lea                 edx, [ebp - 0x244]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0

        $sequence_1 = { 8b450c 8b4d08 8d5401ff 8955fc eb12 8b4508 83c001 }
            // n = 7, score = 200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8d5401ff             | lea                 edx, [ecx + eax - 1]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   eb12                 | jmp                 0x14
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c001               | add                 eax, 1

        $sequence_2 = { c745f400000000 c745f800000000 8b4510 8945fc 8b4510 33d2 b908000000 }
            // n = 7, score = 200
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   33d2                 | xor                 edx, edx
            //   b908000000           | mov                 ecx, 8

        $sequence_3 = { 6a00 8b45f8 50 ff15???????? 8b45f4 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_4 = { 8b0495d0669600 2500000080 8b4df8 8b148dd4669600 81e2ffffff7f 0bc2 }
            // n = 6, score = 200
            //   8b0495d0669600       | mov                 eax, dword ptr [edx*4 + 0x9666d0]
            //   2500000080           | and                 eax, 0x80000000
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b148dd4669600       | mov                 edx, dword ptr [ecx*4 + 0x9666d4]
            //   81e2ffffff7f         | and                 edx, 0x7fffffff
            //   0bc2                 | or                  eax, edx

        $sequence_5 = { 8945d8 c745e400000000 c745fc00000000 68???????? }
            // n = 4, score = 200
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   68????????           |                     

        $sequence_6 = { 837d0800 7406 837d0c00 7502 eb64 8b450c }
            // n = 6, score = 200
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7406                 | je                  8
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7502                 | jne                 4
            //   eb64                 | jmp                 0x66
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_7 = { 89048dd0669600 8b55fc 8b45fc 8b0c85d0669600 890c95d0669600 8b55fc }
            // n = 6, score = 200
            //   89048dd0669600       | mov                 dword ptr [ecx*4 + 0x9666d0], eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b0c85d0669600       | mov                 ecx, dword ptr [eax*4 + 0x9666d0]
            //   890c95d0669600       | mov                 dword ptr [edx*4 + 0x9666d0], ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_8 = { 890d???????? c705????????00000000 a1???????? 8b0c85d0669600 894dfc }
            // n = 5, score = 200
            //   890d????????         |                     
            //   c705????????00000000     |     
            //   a1????????           |                     
            //   8b0c85d0669600       | mov                 ecx, dword ptr [eax*4 + 0x9666d0]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx

        $sequence_9 = { c745f400000000 c745f800000000 c745fc00000000 837d0800 7416 837d0c00 7410 }
            // n = 7, score = 200
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7416                 | je                  0x18
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7410                 | je                  0x12

    condition:
        7 of them and filesize < 73728
}