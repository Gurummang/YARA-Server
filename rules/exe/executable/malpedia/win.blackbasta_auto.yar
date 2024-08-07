rule win_blackbasta_auto {

    meta:
        atk_type = "win.blackbasta."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.blackbasta."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbasta"
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
        $sequence_0 = { ff7590 8bcf e8???????? 84c0 751f 384704 7507 }
            // n = 7, score = 100
            //   ff7590               | push                dword ptr [ebp - 0x70]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   751f                 | jne                 0x21
            //   384704               | cmp                 byte ptr [edi + 4], al
            //   7507                 | jne                 9

        $sequence_1 = { 89b574ffffff 894588 89458c e8???????? 84c0 755d 384304 }
            // n = 7, score = 100
            //   89b574ffffff         | mov                 dword ptr [ebp - 0x8c], esi
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   89458c               | mov                 dword ptr [ebp - 0x74], eax
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   755d                 | jne                 0x5f
            //   384304               | cmp                 byte ptr [ebx + 4], al

        $sequence_2 = { 5b 8b4df4 64890d00000000 8d656c 5d c3 8d4d30 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   8d656c               | lea                 esp, [ebp + 0x6c]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8d4d30               | lea                 ecx, [ebp + 0x30]

        $sequence_3 = { e8???????? 83c404 85c0 0f849d010000 8d5823 83e3e0 8943fc }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   0f849d010000         | je                  0x1a3
            //   8d5823               | lea                 ebx, [eax + 0x23]
            //   83e3e0               | and                 ebx, 0xffffffe0
            //   8943fc               | mov                 dword ptr [ebx - 4], eax

        $sequence_4 = { c745e000000000 c745e40f000000 c645d000 c745fc00000000 ff734c e8???????? 83c404 }
            // n = 7, score = 100
            //   c745e000000000       | mov                 dword ptr [ebp - 0x20], 0
            //   c745e40f000000       | mov                 dword ptr [ebp - 0x1c], 0xf
            //   c645d000             | mov                 byte ptr [ebp - 0x30], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   ff734c               | push                dword ptr [ebx + 0x4c]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_5 = { b867666666 c645e800 f7ea c1fa05 8bc2 c1e81f 03c2 }
            // n = 7, score = 100
            //   b867666666           | mov                 eax, 0x66666667
            //   c645e800             | mov                 byte ptr [ebp - 0x18], 0
            //   f7ea                 | imul                edx
            //   c1fa05               | sar                 edx, 5
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03c2                 | add                 eax, edx

        $sequence_6 = { 85f6 7462 8b7d28 3bf7 7416 0f1f440000 8bce }
            // n = 7, score = 100
            //   85f6                 | test                esi, esi
            //   7462                 | je                  0x64
            //   8b7d28               | mov                 edi, dword ptr [ebp + 0x28]
            //   3bf7                 | cmp                 esi, edi
            //   7416                 | je                  0x18
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   8bce                 | mov                 ecx, esi

        $sequence_7 = { 56 e8???????? 83463008 83c410 0fb6c3 81c500020000 8b5c2474 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   83463008             | add                 dword ptr [esi + 0x30], 8
            //   83c410               | add                 esp, 0x10
            //   0fb6c3               | movzx               eax, bl
            //   81c500020000         | add                 ebp, 0x200
            //   8b5c2474             | mov                 ebx, dword ptr [esp + 0x74]

        $sequence_8 = { 8d4dc0 e8???????? 837e1401 741a 837dec01 740d 8d45d8 }
            // n = 7, score = 100
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   e8????????           |                     
            //   837e1401             | cmp                 dword ptr [esi + 0x14], 1
            //   741a                 | je                  0x1c
            //   837dec01             | cmp                 dword ptr [ebp - 0x14], 1
            //   740d                 | je                  0xf
            //   8d45d8               | lea                 eax, [ebp - 0x28]

        $sequence_9 = { 83c410 8bce 50 68???????? e8???????? 8bf0 c78574ffffff00000000 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   8bce                 | mov                 ecx, esi
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   c78574ffffff00000000     | mov    dword ptr [ebp - 0x8c], 0

    condition:
        7 of them and filesize < 1758208
}