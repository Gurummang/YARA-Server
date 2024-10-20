rule win_regin_auto {

    meta:
        atk_type = "win.regin."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.regin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.regin"
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
        $sequence_0 = { 49 8363f000 48 8d0504230000 49 8943d8 }
            // n = 6, score = 100
            //   49                   | dec                 ecx
            //   8363f000             | and                 dword ptr [ebx - 0x10], 0
            //   48                   | dec                 eax
            //   8d0504230000         | lea                 eax, [0x2304]
            //   49                   | dec                 ecx
            //   8943d8               | mov                 dword ptr [ebx - 0x28], eax

        $sequence_1 = { 48 89442438 b800210000 c7442430204e0000 89442428 }
            // n = 5, score = 100
            //   48                   | dec                 eax
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   b800210000           | mov                 eax, 0x2100
            //   c7442430204e0000     | mov                 dword ptr [esp + 0x30], 0x4e20
            //   89442428             | mov                 dword ptr [esp + 0x28], eax

        $sequence_2 = { 85c0 740c 8b05???????? 39442460 7405 }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   8b05????????         |                     
            //   39442460             | cmp                 dword ptr [esp + 0x60], eax
            //   7405                 | je                  7

        $sequence_3 = { c1e802 41 ffc0 48 8d4c2470 41 }
            // n = 6, score = 100
            //   c1e802               | shr                 eax, 2
            //   41                   | inc                 ecx
            //   ffc0                 | inc                 eax
            //   48                   | dec                 eax
            //   8d4c2470             | lea                 ecx, [esp + 0x70]
            //   41                   | inc                 ecx

        $sequence_4 = { 44 8bc1 48 8b0d???????? ff15???????? }
            // n = 5, score = 100
            //   44                   | inc                 esp
            //   8bc1                 | mov                 eax, ecx
            //   48                   | dec                 eax
            //   8b0d????????         |                     
            //   ff15????????         |                     

        $sequence_5 = { 48 89442448 48 89442450 b82375f1ba }
            // n = 5, score = 100
            //   48                   | dec                 eax
            //   89442448             | mov                 dword ptr [esp + 0x48], eax
            //   48                   | dec                 eax
            //   89442450             | mov                 dword ptr [esp + 0x50], eax
            //   b82375f1ba           | mov                 eax, 0xbaf17523

        $sequence_6 = { 33c0 48 83c428 c3 48 83ec28 33c9 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax
            //   83c428               | add                 esp, 0x28
            //   c3                   | ret                 
            //   48                   | dec                 eax
            //   83ec28               | sub                 esp, 0x28
            //   33c9                 | xor                 ecx, ecx

        $sequence_7 = { 0f45df 8bc3 48 8b5c2448 }
            // n = 4, score = 100
            //   0f45df               | cmovne              ebx, edi
            //   8bc3                 | mov                 eax, ebx
            //   48                   | dec                 eax
            //   8b5c2448             | mov                 ebx, dword ptr [esp + 0x48]

        $sequence_8 = { 84c0 44 8d7304 0f45f8 8d4302 44 84c0 }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   44                   | inc                 esp
            //   8d7304               | lea                 esi, [ebx + 4]
            //   0f45f8               | cmovne              edi, eax
            //   8d4302               | lea                 eax, [ebx + 2]
            //   44                   | inc                 esp
            //   84c0                 | test                al, al

        $sequence_9 = { 48 8bfb 8bc7 48 8b5c2430 48 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   8bfb                 | mov                 edi, ebx
            //   8bc7                 | mov                 eax, edi
            //   48                   | dec                 eax
            //   8b5c2430             | mov                 ebx, dword ptr [esp + 0x30]
            //   48                   | dec                 eax

    condition:
        7 of them and filesize < 49152
}