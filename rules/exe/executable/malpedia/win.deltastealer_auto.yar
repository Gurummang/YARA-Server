rule win_deltastealer_auto {

    meta:
        atk_type = "win.deltastealer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.deltastealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltastealer"
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
        $sequence_0 = { 4883c428 c3 56 57 53 4883ec30 4c89c6 }
            // n = 7, score = 200
            //   4883c428             | mov                 eax, 0x100
            //   c3                   | dec                 eax
            //   56                   | mov                 dword ptr [esp + 0x50], ecx
            //   57                   | inc                 ecx
            //   53                   | movups              xmm0, xmmword ptr [ebp + 0x640]
            //   4883ec30             | inc                 ecx
            //   4c89c6               | mov                 dword ptr [ebp + 0x90], 0x10

        $sequence_1 = { 4d01c1 4c894c2420 4c89442428 c744243803001100 c744244803001100 488d5c2430 4c8d742440 }
            // n = 7, score = 200
            //   4d01c1               | mov                 edx, dword ptr [esp + 0x38]
            //   4c894c2420           | dec                 ecx
            //   4c89442428           | mov                 dword ptr [edi + 0x18], ecx
            //   c744243803001100     | inc                 ecx
            //   c744244803001100     | mov                 dword ptr [edi + 0x20], 1
            //   488d5c2430           | inc                 ecx
            //   4c8d742440           | mov                 dword ptr [edi + 0x24], eax

        $sequence_2 = { 57 53 4883ec40 4889d3 488b01 488b7008 488b7810 }
            // n = 7, score = 200
            //   57                   | mov                 dword ptr [ebx - 0x2c], esp
            //   53                   | dec                 eax
            //   4883ec40             | mov                 dword ptr [esp + 0x58], esi
            //   4889d3               | dec                 esp
            //   488b01               | mov                 dword ptr [esp + 0x290], esi
            //   488b7008             | mov                 byte ptr [ebx + 0x12a], 0
            //   488b7810             | cmp                 byte ptr [ebx + 0x121], 2

        $sequence_3 = { 84c0 7416 4180bc240802000000 750b 488b842448010000 c60001 4584f6 }
            // n = 7, score = 200
            //   84c0                 | ret                 
            //   7416                 | push                esi
            //   4180bc240802000000     | push    edi
            //   750b                 | dec                 eax
            //   488b842448010000     | sub                 esp, 0x28
            //   c60001               | dec                 eax
            //   4584f6               | mov                 esi, ecx

        $sequence_4 = { e8???????? 498b7610 31db 4839df 741e 8a041e 8d48bf }
            // n = 7, score = 200
            //   e8????????           |                     
            //   498b7610             | cmove               ebx, esi
            //   31db                 | jne                 0x1e7
            //   4839df               | dec                 eax
            //   741e                 | cmp                 dword ptr [ebx], 0
            //   8a041e               | mov                 ecx, 1
            //   8d48bf               | dec                 eax

        $sequence_5 = { 89d7 48ffc3 49895e10 49f7e2 0f80a8000000 400fb6d7 4801d0 }
            // n = 7, score = 200
            //   89d7                 | dec                 ecx
            //   48ffc3               | mov                 edi, eax
            //   49895e10             | jmp                 0x32c
            //   49f7e2               | jae                 0x3ab
            //   0f80a8000000         | test                dl, dl
            //   400fb6d7             | jne                 0x3ab
            //   4801d0               | inc                 esp

        $sequence_6 = { c6474001 4889f9 e8???????? 4885c0 7438 4885d2 7433 }
            // n = 7, score = 200
            //   c6474001             | cmovne              edx, esp
            //   4889f9               | jne                 0xaf0
            //   e8????????           |                     
            //   4885c0               | dec                 eax
            //   7438                 | mov                 eax, dword ptr [edi + 0x20]
            //   4885d2               | mov                 cl, byte ptr [edi + eax + 0x27]
            //   7433                 | dec                 ecx

        $sequence_7 = { e8???????? 4489e3 488d4c2460 e8???????? 4989c7 eb21 4584e4 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   4489e3               | mov                 dword ptr [esp + 0x40], eax
            //   488d4c2460           | dec                 eax
            //   e8????????           |                     
            //   4989c7               | test                ebx, ebx
            //   eb21                 | je                  0xc65
            //   4584e4               | pop                 eax

        $sequence_8 = { 48895c2420 488d7c2430 41b830000000 41b910000000 4889f9 e8???????? 488b7f18 }
            // n = 7, score = 200
            //   48895c2420           | pop                 ebx
            //   488d7c2430           | pop                 edi
            //   41b830000000         | pop                 esi
            //   41b910000000         | dec                 eax
            //   4889f9               | and                 dword ptr [esi + 0x30], 0
            //   e8????????           |                     
            //   488b7f18             | dec                 eax

        $sequence_9 = { 6601c8 0f92c2 81f9ffff0000 0f87d8feffff 84d2 0f85d0feffff 4d85f6 }
            // n = 7, score = 200
            //   6601c8               | dec                 esp
            //   0f92c2               | mov                 ecx, edi
            //   81f9ffff0000         | mov                 eax, dword ptr [eax + 0x4c]
            //   0f87d8feffff         | xor                 edi, edi
            //   84d2                 | test                eax, eax
            //   0f85d0feffff         | cmovle              eax, edi
            //   4d85f6               | sub                 ebp, eax

    condition:
        7 of them and filesize < 3532800
}