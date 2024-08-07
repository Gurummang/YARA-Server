rule win_buhtrap_auto {

    meta:
        atk_type = "win.buhtrap."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.buhtrap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.buhtrap"
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
        $sequence_0 = { 59 59 84c0 0f8435010000 }
            // n = 4, score = 500
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al
            //   0f8435010000         | je                  0x13b

        $sequence_1 = { 7423 8b44240c 33d2 6a64 59 f7f1 }
            // n = 6, score = 400
            //   7423                 | je                  0x25
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   33d2                 | xor                 edx, edx
            //   6a64                 | push                0x64
            //   59                   | pop                 ecx
            //   f7f1                 | div                 ecx

        $sequence_2 = { c3 b301 ebe1 55 8bec 83ec18 }
            // n = 6, score = 400
            //   c3                   | ret                 
            //   b301                 | mov                 bl, 1
            //   ebe1                 | jmp                 0xffffffe3
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec18               | sub                 esp, 0x18

        $sequence_3 = { 6a00 50 8d442414 c744242c04000000 }
            // n = 4, score = 400
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   c744242c04000000     | mov                 dword ptr [esp + 0x2c], 4

        $sequence_4 = { 6a06 8bce e8???????? 8a1d???????? 56 }
            // n = 5, score = 400
            //   6a06                 | push                6
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8a1d????????         |                     
            //   56                   | push                esi

        $sequence_5 = { 0f8489000000 837d1400 747b 6a09 59 33c0 8d7c242c }
            // n = 7, score = 400
            //   0f8489000000         | je                  0x8f
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0
            //   747b                 | je                  0x7d
            //   6a09                 | push                9
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   8d7c242c             | lea                 edi, [esp + 0x2c]

        $sequence_6 = { 7405 e8???????? 85f6 7907 32c0 e9???????? 8365f000 }
            // n = 7, score = 400
            //   7405                 | je                  7
            //   e8????????           |                     
            //   85f6                 | test                esi, esi
            //   7907                 | jns                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   8365f000             | and                 dword ptr [ebp - 0x10], 0

        $sequence_7 = { ffd6 57 ffd6 33c0 85db 0f94c0 5f }
            // n = 7, score = 400
            //   ffd6                 | call                esi
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   33c0                 | xor                 eax, eax
            //   85db                 | test                ebx, ebx
            //   0f94c0               | sete                al
            //   5f                   | pop                 edi

        $sequence_8 = { 754e 6a01 53 50 }
            // n = 4, score = 100
            //   754e                 | jne                 0x50
            //   6a01                 | push                1
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_9 = { 53 68???????? 890e 894604 e8???????? 50 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   68????????           |                     
            //   890e                 | mov                 dword ptr [esi], ecx
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_10 = { 897dfc e8???????? 59 84c0 0f8497000000 3bdf }
            // n = 6, score = 100
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al
            //   0f8497000000         | je                  0x9d
            //   3bdf                 | cmp                 ebx, edi

        $sequence_11 = { 6aff ff742420 ff7624 ffd7 ff742418 e8???????? }
            // n = 6, score = 100
            //   6aff                 | push                -1
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   ff7624               | push                dword ptr [esi + 0x24]
            //   ffd7                 | call                edi
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   e8????????           |                     

        $sequence_12 = { ffd7 6a00 689385e784 6a28 68???????? }
            // n = 5, score = 100
            //   ffd7                 | call                edi
            //   6a00                 | push                0
            //   689385e784           | push                0x84e78593
            //   6a28                 | push                0x28
            //   68????????           |                     

        $sequence_13 = { 894624 8b442414 894604 a808 7466 }
            // n = 5, score = 100
            //   894624               | mov                 dword ptr [esi + 0x24], eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   a808                 | test                al, 8
            //   7466                 | je                  0x68

        $sequence_14 = { 753d 8b4e2c 83c104 e8???????? e8???????? }
            // n = 5, score = 100
            //   753d                 | jne                 0x3f
            //   8b4e2c               | mov                 ecx, dword ptr [esi + 0x2c]
            //   83c104               | add                 ecx, 4
            //   e8????????           |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 131072
}