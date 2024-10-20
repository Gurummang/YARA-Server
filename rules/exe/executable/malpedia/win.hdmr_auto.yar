rule win_hdmr_auto {

    meta:
        atk_type = "win.hdmr."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hdmr."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hdmr"
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
        $sequence_0 = { 8945e0 85c0 7461 8d0cbd40d04100 8901 8305????????20 8b11 }
            // n = 7, score = 100
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   85c0                 | test                eax, eax
            //   7461                 | je                  0x63
            //   8d0cbd40d04100       | lea                 ecx, [edi*4 + 0x41d040]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8305????????20       |                     
            //   8b11                 | mov                 edx, dword ptr [ecx]

        $sequence_1 = { 8945ec 894df0 894dfc 8b16 8b523c 50 }
            // n = 6, score = 100
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8b523c               | mov                 edx, dword ptr [edx + 0x3c]
            //   50                   | push                eax

        $sequence_2 = { c1e810 4a 75e6 eb07 }
            // n = 4, score = 100
            //   c1e810               | shr                 eax, 0x10
            //   4a                   | dec                 edx
            //   75e6                 | jne                 0xffffffe8
            //   eb07                 | jmp                 9

        $sequence_3 = { 56 8b7508 68fe070000 8d85fef7ffff 6a00 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   68fe070000           | push                0x7fe
            //   8d85fef7ffff         | lea                 eax, [ebp - 0x802]
            //   6a00                 | push                0

        $sequence_4 = { 85db 0f8492010000 8b8d70ffffff 0fb709 }
            // n = 4, score = 100
            //   85db                 | test                ebx, ebx
            //   0f8492010000         | je                  0x198
            //   8b8d70ffffff         | mov                 ecx, dword ptr [ebp - 0x90]
            //   0fb709               | movzx               ecx, word ptr [ecx]

        $sequence_5 = { 250000ff00 81e3000000ff 33c3 8bda 81e2ff000000 }
            // n = 5, score = 100
            //   250000ff00           | and                 eax, 0xff0000
            //   81e3000000ff         | and                 ebx, 0xff000000
            //   33c3                 | xor                 eax, ebx
            //   8bda                 | mov                 ebx, edx
            //   81e2ff000000         | and                 edx, 0xff

        $sequence_6 = { 0fb701 0fb71c0f 2bc3 2bc2 }
            // n = 4, score = 100
            //   0fb701               | movzx               eax, word ptr [ecx]
            //   0fb71c0f             | movzx               ebx, word ptr [edi + ecx]
            //   2bc3                 | sub                 eax, ebx
            //   2bc2                 | sub                 eax, edx

        $sequence_7 = { 75ea 8a03 3c61 0fbec0 }
            // n = 4, score = 100
            //   75ea                 | jne                 0xffffffec
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   3c61                 | cmp                 al, 0x61
            //   0fbec0               | movsx               eax, al

        $sequence_8 = { 8b400c 51 52 8bce ffd0 5e 5b }
            // n = 7, score = 100
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8bce                 | mov                 ecx, esi
            //   ffd0                 | call                eax
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_9 = { 50 ff15???????? 8d8c24780a0000 51 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8c24780a0000       | lea                 ecx, [esp + 0xa78]
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 284672
}