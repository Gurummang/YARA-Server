rule win_roll_sling_auto {

    meta:
        atk_type = "win.roll_sling."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.roll_sling."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roll_sling"
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
        $sequence_0 = { 33c9 ff15???????? 48898424a8000000 4c8bf8 4885c0 7431 ff15???????? }
            // n = 7, score = 100
            //   33c9                 | lea                 ecx, [eax + ecx*2]
            //   ff15????????         |                     
            //   48898424a8000000     | inc                 esp
            //   4c8bf8               | mov                 eax, dword ptr [edi + ecx*4]
            //   4885c0               | and                 eax, 1
            //   7431                 | dec                 ecx
            //   ff15????????         |                     

        $sequence_1 = { 4c8b7dd8 3b5c2440 7306 488b4dd0 ebb9 498bcd }
            // n = 6, score = 100
            //   4c8b7dd8             | lea                 edi, [0x15620]
            //   3b5c2440             | jmp                 0x83c
            //   7306                 | dec                 eax
            //   488b4dd0             | mov                 eax, dword ptr [ebx]
            //   ebb9                 | dec                 eax
            //   498bcd               | test                eax, eax

        $sequence_2 = { b80d000000 41bf0a000000 440f44f8 33db 4c03f7 0f1f4000 66660f1f840000000000 }
            // n = 7, score = 100
            //   b80d000000           | cmovb               ebx, eax
            //   41bf0a000000         | dec                 eax
            //   440f44f8             | lea                 eax, [ebx + 1]
            //   33db                 | dec                 eax
            //   4c03f7               | cmp                 eax, 0x1000
            //   0f1f4000             | jb                  0x4db
            //   66660f1f840000000000     | dec    edx

        $sequence_3 = { 488b55d0 4883fa10 0f824effffff 48ffc2 488b4db8 488bc1 4881fa00100000 }
            // n = 7, score = 100
            //   488b55d0             | cmp                 esp, eax
            //   4883fa10             | jl                  0xa0e
            //   0f824effffff         | dec                 eax
            //   48ffc2               | mov                 ebx, dword ptr [ecx + 0x30]
            //   488b4db8             | dec                 eax
            //   488bc1               | sub                 ebx, dword ptr [ebp + 0x30]
            //   4881fa00100000       | je                  0xb67

        $sequence_4 = { 488905???????? 498bde 4883fa10 480f431d???????? 4803d9 41b823000000 }
            // n = 6, score = 100
            //   488905????????       |                     
            //   498bde               | inc                 ebp
            //   4883fa10             | xor                 ecx, ecx
            //   480f431d????????     |                     
            //   4803d9               | nop                 
            //   41b823000000         | dec                 esp

        $sequence_5 = { 0f86ec000000 eb0a 48b92700000000000080 e8???????? 4885c0 0f84cc000000 488d7827 }
            // n = 7, score = 100
            //   0f86ec000000         | mov                 edi, dword ptr [esp + 0x20]
            //   eb0a                 | dec                 esp
            //   48b92700000000000080     | mov    ebp, dword ptr [esp + 0x30]
            //   e8????????           |                     
            //   4885c0               | dec                 ebp
            //   0f84cc000000         | test                eax, eax
            //   488d7827             | je                  0x448

        $sequence_6 = { e8???????? 41c6042f00 48893e 488bc6 4c8b6c2460 488b7c2458 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   41c6042f00           | dec                 eax
            //   48893e               | mov                 edx, esi
            //   488bc6               | dec                 ecx
            //   4c8b6c2460           | mov                 ecx, esp
            //   488b7c2458           | dec                 ecx

        $sequence_7 = { 41b801010000 e8???????? 418bc6 4d8d4d10 4c8d3d04180100 41be04000000 }
            // n = 6, score = 100
            //   41b801010000         | mov                 eax, edx
            //   e8????????           |                     
            //   418bc6               | dec                 eax
            //   4d8d4d10             | shr                 eax, 0x1e
            //   4c8d3d04180100       | and                 eax, 1
            //   41be04000000         | dec                 esp

        $sequence_8 = { eb14 4889742420 4c8d4da0 488bd6 }
            // n = 4, score = 100
            //   eb14                 | dec                 esp
            //   4889742420           | lea                 edi, [0x11804]
            //   4c8d4da0             | inc                 ecx
            //   488bd6               | mov                 esi, 4

        $sequence_9 = { 7476 48895c2438 4533c9 4533c0 48897c2420 bad8070000 }
            // n = 6, score = 100
            //   7476                 | mov                 ecx, eax
            //   48895c2438           | dec                 eax
            //   4533c9               | test                eax, eax
            //   4533c0               | dec                 eax
            //   48897c2420           | lea                 eax, [ecx + 0x27]
            //   bad8070000           | dec                 eax

    condition:
        7 of them and filesize < 299008
}