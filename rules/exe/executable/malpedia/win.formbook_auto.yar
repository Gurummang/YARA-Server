rule win_formbook_auto {

    meta:
        atk_type = "win.formbook."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.formbook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
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
        $sequence_0 = { 5b 5f 5e 8be5 5d c3 8d0476 }
            // n = 7, score = 2200
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8d0476               | lea                 eax, [esi + esi*2]

        $sequence_1 = { 6a0d 8d8500fcffff 50 56 e8???????? 8d8d00fcffff 51 }
            // n = 7, score = 2200
            //   6a0d                 | push                0xd
            //   8d8500fcffff         | lea                 eax, [ebp - 0x400]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d8d00fcffff         | lea                 ecx, [ebp - 0x400]
            //   51                   | push                ecx

        $sequence_2 = { 56 e8???????? 8d4df4 51 56 e8???????? 8d55e4 }
            // n = 7, score = 2200
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d55e4               | lea                 edx, [ebp - 0x1c]

        $sequence_3 = { c3 3c04 752b 8b7518 8b0e 8b5510 8b7d14 }
            // n = 7, score = 2200
            //   c3                   | ret                 
            //   3c04                 | cmp                 al, 4
            //   752b                 | jne                 0x2d
            //   8b7518               | mov                 esi, dword ptr [ebp + 0x18]
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8b7d14               | mov                 edi, dword ptr [ebp + 0x14]

        $sequence_4 = { 56 e8???????? 83c418 395df8 0f85a0000000 8b7d18 395f10 }
            // n = 7, score = 2200
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   395df8               | cmp                 dword ptr [ebp - 8], ebx
            //   0f85a0000000         | jne                 0xa6
            //   8b7d18               | mov                 edi, dword ptr [ebp + 0x18]
            //   395f10               | cmp                 dword ptr [edi + 0x10], ebx

        $sequence_5 = { c745fc01000000 e8???????? 6a14 8d4dec 51 50 }
            // n = 6, score = 2200
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   e8????????           |                     
            //   6a14                 | push                0x14
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_6 = { e8???????? 83c428 8906 85c0 75a8 5f 33c0 }
            // n = 7, score = 2200
            //   e8????????           |                     
            //   83c428               | add                 esp, 0x28
            //   8906                 | mov                 dword ptr [esi], eax
            //   85c0                 | test                eax, eax
            //   75a8                 | jne                 0xffffffaa
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 56 e8???????? 6a03 ba5c000000 57 56 66891446 }
            // n = 7, score = 2200
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a03                 | push                3
            //   ba5c000000           | mov                 edx, 0x5c
            //   57                   | push                edi
            //   56                   | push                esi
            //   66891446             | mov                 word ptr [esi + eax*2], dx

        $sequence_8 = { 3b75d0 72c0 8d55f8 52 e8???????? }
            // n = 5, score = 2200
            //   3b75d0               | cmp                 esi, dword ptr [ebp - 0x30]
            //   72c0                 | jb                  0xffffffc2
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_9 = { 8d8df6f7ffff 51 c745fc00000000 668985f4f7ffff e8???????? 8b7508 }
            // n = 6, score = 2200
            //   8d8df6f7ffff         | lea                 ecx, [ebp - 0x80a]
            //   51                   | push                ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   668985f4f7ffff       | mov                 word ptr [ebp - 0x80c], ax
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 371712
}