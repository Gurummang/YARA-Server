rule win_kpot_stealer_auto {

    meta:
        atk_type = "win.kpot_stealer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.kpot_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kpot_stealer"
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
        $sequence_0 = { 03c6 50 ff75f4 e8???????? 59 59 8d4df8 }
            // n = 7, score = 500
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8d4df8               | lea                 ecx, [ebp - 8]

        $sequence_1 = { 0bce 8bc1 c1e804 33c2 250f0f0f0f 33d0 }
            // n = 6, score = 500
            //   0bce                 | or                  ecx, esi
            //   8bc1                 | mov                 eax, ecx
            //   c1e804               | shr                 eax, 4
            //   33c2                 | xor                 eax, edx
            //   250f0f0f0f           | and                 eax, 0xf0f0f0f
            //   33d0                 | xor                 edx, eax

        $sequence_2 = { 55 8bec ff7508 ff15???????? 83f8ff 7409 a8a7 }
            // n = 7, score = 500
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   7409                 | je                  0xb
            //   a8a7                 | test                al, 0xa7

        $sequence_3 = { 8b4604 8b5df4 03d2 8d445802 e8???????? }
            // n = 5, score = 500
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   8b5df4               | mov                 ebx, dword ptr [ebp - 0xc]
            //   03d2                 | add                 edx, edx
            //   8d445802             | lea                 eax, [eax + ebx*2 + 2]
            //   e8????????           |                     

        $sequence_4 = { 85c0 7427 8b45f8 03c6 50 }
            // n = 5, score = 500
            //   85c0                 | test                eax, eax
            //   7427                 | je                  0x29
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax

        $sequence_5 = { 57 8bf8 8b4518 0fb67005 }
            // n = 4, score = 500
            //   57                   | push                edi
            //   8bf8                 | mov                 edi, eax
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   0fb67005             | movzx               esi, byte ptr [eax + 5]

        $sequence_6 = { 8b45f4 c1e918 884b07 8945fc 8b45f0 83c308 ff4dec }
            // n = 7, score = 500
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   c1e918               | shr                 ecx, 0x18
            //   884b07               | mov                 byte ptr [ebx + 7], cl
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83c308               | add                 ebx, 8
            //   ff4dec               | dec                 dword ptr [ebp - 0x14]

        $sequence_7 = { 5e 5b c9 c3 0fb70f 6685c9 7440 }
            // n = 7, score = 500
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   0fb70f               | movzx               ecx, word ptr [edi]
            //   6685c9               | test                cx, cx
            //   7440                 | je                  0x42

        $sequence_8 = { a8a7 7405 33c0 40 5d }
            // n = 5, score = 500
            //   a8a7                 | test                al, 0xa7
            //   7405                 | je                  7
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   5d                   | pop                 ebp

        $sequence_9 = { 8bc1 c1e810 884306 8b45f4 }
            // n = 4, score = 500
            //   8bc1                 | mov                 eax, ecx
            //   c1e810               | shr                 eax, 0x10
            //   884306               | mov                 byte ptr [ebx + 6], al
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 219136
}