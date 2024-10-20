rule win_slave_auto {

    meta:
        atk_type = "win.slave."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.slave."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slave"
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
        $sequence_0 = { ff15???????? 85c0 0f84e0020000 6a04 6800100000 6800100000 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84e0020000         | je                  0x2e6
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   6800100000           | push                0x1000

        $sequence_1 = { 7514 66837b0600 7405 8a4306 }
            // n = 4, score = 300
            //   7514                 | jne                 0x16
            //   66837b0600           | cmp                 word ptr [ebx + 6], 0
            //   7405                 | je                  7
            //   8a4306               | mov                 al, byte ptr [ebx + 6]

        $sequence_2 = { 0fbf4720 33d2 50 0fb6c1 68???????? 83c008 }
            // n = 6, score = 300
            //   0fbf4720             | movsx               eax, word ptr [edi + 0x20]
            //   33d2                 | xor                 edx, edx
            //   50                   | push                eax
            //   0fb6c1               | movzx               eax, cl
            //   68????????           |                     
            //   83c008               | add                 eax, 8

        $sequence_3 = { 730d 810e00000800 808b0603000040 8b4610 808b0603000010 8a55ff }
            // n = 6, score = 300
            //   730d                 | jae                 0xf
            //   810e00000800         | or                  dword ptr [esi], 0x80000
            //   808b0603000040       | or                  byte ptr [ebx + 0x306], 0x40
            //   8b4610               | mov                 eax, dword ptr [esi + 0x10]
            //   808b0603000010       | or                  byte ptr [ebx + 0x306], 0x10
            //   8a55ff               | mov                 dl, byte ptr [ebp - 1]

        $sequence_4 = { c74710d5000000 eb10 c7471095000000 eb07 c7471085000000 f70700400000 742f }
            // n = 7, score = 300
            //   c74710d5000000       | mov                 dword ptr [edi + 0x10], 0xd5
            //   eb10                 | jmp                 0x12
            //   c7471095000000       | mov                 dword ptr [edi + 0x10], 0x95
            //   eb07                 | jmp                 9
            //   c7471085000000       | mov                 dword ptr [edi + 0x10], 0x85
            //   f70700400000         | test                dword ptr [edi], 0x4000
            //   742f                 | je                  0x31

        $sequence_5 = { c1c90d 33c8 8b7dd4 8b45e8 03fa c1c802 33c8 }
            // n = 7, score = 300
            //   c1c90d               | ror                 ecx, 0xd
            //   33c8                 | xor                 ecx, eax
            //   8b7dd4               | mov                 edi, dword ptr [ebp - 0x2c]
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   03fa                 | add                 edi, edx
            //   c1c802               | ror                 eax, 2
            //   33c8                 | xor                 ecx, eax

        $sequence_6 = { 83ec24 53 32c0 32c9 56 8b7508 }
            // n = 6, score = 300
            //   83ec24               | sub                 esp, 0x24
            //   53                   | push                ebx
            //   32c0                 | xor                 al, al
            //   32c9                 | xor                 cl, cl
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_7 = { 8a8e08010000 f6c210 0f8411040000 8b8610030000 0b8614030000 0f84c2000000 f6c240 }
            // n = 7, score = 300
            //   8a8e08010000         | mov                 cl, byte ptr [esi + 0x108]
            //   f6c210               | test                dl, 0x10
            //   0f8411040000         | je                  0x417
            //   8b8610030000         | mov                 eax, dword ptr [esi + 0x310]
            //   0b8614030000         | or                  eax, dword ptr [esi + 0x314]
            //   0f84c2000000         | je                  0xc8
            //   f6c240               | test                dl, 0x40

        $sequence_8 = { 8bc6 c1c806 33c8 8bc3 3345d4 034da0 }
            // n = 6, score = 300
            //   8bc6                 | mov                 eax, esi
            //   c1c806               | ror                 eax, 6
            //   33c8                 | xor                 ecx, eax
            //   8bc3                 | mov                 eax, ebx
            //   3345d4               | xor                 eax, dword ptr [ebp - 0x2c]
            //   034da0               | add                 ecx, dword ptr [ebp - 0x60]

        $sequence_9 = { 8bd8 0b5df4 2345f4 03ca 235de0 0bd8 8b55ac }
            // n = 7, score = 300
            //   8bd8                 | mov                 ebx, eax
            //   0b5df4               | or                  ebx, dword ptr [ebp - 0xc]
            //   2345f4               | and                 eax, dword ptr [ebp - 0xc]
            //   03ca                 | add                 ecx, edx
            //   235de0               | and                 ebx, dword ptr [ebp - 0x20]
            //   0bd8                 | or                  ebx, eax
            //   8b55ac               | mov                 edx, dword ptr [ebp - 0x54]

    condition:
        7 of them and filesize < 532480
}