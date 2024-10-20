rule win_chthonic_auto {

    meta:
        atk_type = "win.chthonic."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.chthonic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chthonic"
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
        $sequence_0 = { 7459 4f 8bf0 8bcf d3ee 83e601 }
            // n = 6, score = 600
            //   7459                 | je                  0x5b
            //   4f                   | dec                 edi
            //   8bf0                 | mov                 esi, eax
            //   8bcf                 | mov                 ecx, edi
            //   d3ee                 | shr                 esi, cl
            //   83e601               | and                 esi, 1

        $sequence_1 = { 0f845d010000 4f 8bf0 8bcf }
            // n = 4, score = 600
            //   0f845d010000         | je                  0x163
            //   4f                   | dec                 edi
            //   8bf0                 | mov                 esi, eax
            //   8bcf                 | mov                 ecx, edi

        $sequence_2 = { 81cf00ffffff 47 8a01 8845ff 8d84bdfcfbffff 8b10 }
            // n = 6, score = 600
            //   81cf00ffffff         | or                  edi, 0xffffff00
            //   47                   | inc                 edi
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   8d84bdfcfbffff       | lea                 eax, [ebp + edi*4 - 0x404]
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_3 = { 80e17f 8808 b001 5b c3 55 }
            // n = 6, score = 600
            //   80e17f               | and                 cl, 0x7f
            //   8808                 | mov                 byte ptr [eax], cl
            //   b001                 | mov                 al, 1
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_4 = { 8b75f8 83fe02 0f850d010000 8b4df0 }
            // n = 4, score = 600
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   83fe02               | cmp                 esi, 2
            //   0f850d010000         | jne                 0x113
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_5 = { 016e04 83c703 013e 8b36 83c410 }
            // n = 5, score = 600
            //   016e04               | add                 dword ptr [esi + 4], ebp
            //   83c703               | add                 edi, 3
            //   013e                 | add                 dword ptr [esi], edi
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   83c410               | add                 esp, 0x10

        $sequence_6 = { 5e 0f94c0 5b c9 c3 8b041a }
            // n = 6, score = 600
            //   5e                   | pop                 esi
            //   0f94c0               | sete                al
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   8b041a               | mov                 eax, dword ptr [edx + ebx]

        $sequence_7 = { 53 ff7510 ff7508 e8???????? 85c0 }
            // n = 5, score = 600
            //   53                   | push                ebx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_8 = { 80e17f 8808 b001 5b c3 55 8bec }
            // n = 7, score = 600
            //   80e17f               | and                 cl, 0x7f
            //   8808                 | mov                 byte ptr [eax], cl
            //   b001                 | mov                 al, 1
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_9 = { ff751c ff7518 ff7514 53 ff7510 ff7508 e8???????? }
            // n = 7, score = 600
            //   ff751c               | push                dword ptr [ebp + 0x1c]
            //   ff7518               | push                dword ptr [ebp + 0x18]
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   53                   | push                ebx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 425984
}