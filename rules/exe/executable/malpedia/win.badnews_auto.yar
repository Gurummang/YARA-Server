rule win_badnews_auto {

    meta:
        atk_type = "win.badnews."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.badnews."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badnews"
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
        $sequence_0 = { 50 e8???????? 83c404 68???????? 6804010000 ff15???????? }
            // n = 6, score = 1000
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   68????????           |                     
            //   6804010000           | push                0x104
            //   ff15????????         |                     

        $sequence_1 = { c78534ffffff47657457 c78538ffffff696e646f c7853cffffff77546578 66c78540ffffff7457 }
            // n = 4, score = 900
            //   c78534ffffff47657457     | mov    dword ptr [ebp - 0xcc], 0x57746547
            //   c78538ffffff696e646f     | mov    dword ptr [ebp - 0xc8], 0x6f646e69
            //   c7853cffffff77546578     | mov    dword ptr [ebp - 0xc4], 0x78655477
            //   66c78540ffffff7457     | mov    word ptr [ebp - 0xc0], 0x5774

        $sequence_2 = { c705????????55736572 c705????????33322e64 66c705????????6c6c c605????????00 }
            // n = 4, score = 900
            //   c705????????55736572     |     
            //   c705????????33322e64     |     
            //   66c705????????6c6c     |     
            //   c605????????00       |                     

        $sequence_3 = { eb02 33c9 c0e004 02c1 3423 c0c003 }
            // n = 6, score = 900
            //   eb02                 | jmp                 4
            //   33c9                 | xor                 ecx, ecx
            //   c0e004               | shl                 al, 4
            //   02c1                 | add                 al, cl
            //   3423                 | xor                 al, 0x23
            //   c0c003               | rol                 al, 3

        $sequence_4 = { 8945fc 53 56 57 8d8534ffffff }
            // n = 5, score = 900
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d8534ffffff         | lea                 eax, [ebp - 0xcc]

        $sequence_5 = { 55 8bec 8b450c 3d01020000 }
            // n = 4, score = 900
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   3d01020000           | cmp                 eax, 0x201

        $sequence_6 = { d1f9 68???????? 03c9 51 }
            // n = 4, score = 800
            //   d1f9                 | sar                 ecx, 1
            //   68????????           |                     
            //   03c9                 | add                 ecx, ecx
            //   51                   | push                ecx

        $sequence_7 = { 68???????? 6a1a 68???????? 57 }
            // n = 4, score = 800
            //   68????????           |                     
            //   6a1a                 | push                0x1a
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_8 = { 6a02 68???????? 50 a3???????? }
            // n = 4, score = 800
            //   6a02                 | push                2
            //   68????????           |                     
            //   50                   | push                eax
            //   a3????????           |                     

        $sequence_9 = { 8bf0 56 ff15???????? 50 6a40 }
            // n = 5, score = 700
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a40                 | push                0x40

        $sequence_10 = { 56 ffd3 85c0 7403 83c608 8a06 }
            // n = 6, score = 700
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   83c608               | add                 esi, 8
            //   8a06                 | mov                 al, byte ptr [esi]

        $sequence_11 = { 57 6a00 6880000000 6a04 6a00 6a01 6a04 }
            // n = 7, score = 700
            //   57                   | push                edi
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a04                 | push                4

        $sequence_12 = { ff15???????? 85c0 7405 83c004 }
            // n = 4, score = 700
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   83c004               | add                 eax, 4

        $sequence_13 = { 68???????? ff15???????? b8???????? 83c424 8d5002 668b08 }
            // n = 6, score = 500
            //   68????????           |                     
            //   ff15????????         |                     
            //   b8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8d5002               | lea                 edx, [eax + 2]
            //   668b08               | mov                 cx, word ptr [eax]

        $sequence_14 = { e8???????? 68???????? 8d45f4 c745f4682f0110 50 e8???????? cc }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   c745f4682f0110       | mov                 dword ptr [ebp - 0xc], 0x10012f68
            //   50                   | push                eax
            //   e8????????           |                     
            //   cc                   | int3                

        $sequence_15 = { 83e61f c1f805 c1e606 c1e910 c0e107 8b1485d0a70110 }
            // n = 6, score = 100
            //   83e61f               | and                 esi, 0x1f
            //   c1f805               | sar                 eax, 5
            //   c1e606               | shl                 esi, 6
            //   c1e910               | shr                 ecx, 0x10
            //   c0e107               | shl                 cl, 7
            //   8b1485d0a70110       | mov                 edx, dword ptr [eax*4 + 0x1001a7d0]

        $sequence_16 = { 8d8d54ffffff 8d5101 90 8a01 }
            // n = 4, score = 100
            //   8d8d54ffffff         | lea                 ecx, [ebp - 0xac]
            //   8d5101               | lea                 edx, [ecx + 1]
            //   90                   | nop                 
            //   8a01                 | mov                 al, byte ptr [ecx]

        $sequence_17 = { 7414 8bc2 c1f805 83e21f c1e206 031485d0a70110 }
            // n = 6, score = 100
            //   7414                 | je                  0x16
            //   8bc2                 | mov                 eax, edx
            //   c1f805               | sar                 eax, 5
            //   83e21f               | and                 edx, 0x1f
            //   c1e206               | shl                 edx, 6
            //   031485d0a70110       | add                 edx, dword ptr [eax*4 + 0x1001a7d0]

        $sequence_18 = { 8b048dd0a70110 4e 807d1300 8955e4 c64418050a }
            // n = 5, score = 100
            //   8b048dd0a70110       | mov                 eax, dword ptr [ecx*4 + 0x1001a7d0]
            //   4e                   | dec                 esi
            //   807d1300             | cmp                 byte ptr [ebp + 0x13], 0
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   c64418050a           | mov                 byte ptr [eax + ebx + 5], 0xa

        $sequence_19 = { 58 668986b8000000 668986be010000 c7466848960110 }
            // n = 4, score = 100
            //   58                   | pop                 eax
            //   668986b8000000       | mov                 word ptr [esi + 0xb8], ax
            //   668986be010000       | mov                 word ptr [esi + 0x1be], ax
            //   c7466848960110       | mov                 dword ptr [esi + 0x68], 0x10019648

        $sequence_20 = { 2bc2 8bf0 d1fe 6a55 ff34f5e0470110 ff7508 e8???????? }
            // n = 7, score = 100
            //   2bc2                 | sub                 eax, edx
            //   8bf0                 | mov                 esi, eax
            //   d1fe                 | sar                 esi, 1
            //   6a55                 | push                0x55
            //   ff34f5e0470110       | push                dword ptr [esi*8 + 0x100147e0]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_21 = { 41 84c0 75f9 2bce 741c 804415ec03 }
            // n = 6, score = 100
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   2bce                 | sub                 ecx, esi
            //   741c                 | je                  0x1e
            //   804415ec03           | add                 byte ptr [ebp + edx - 0x14], 3

    condition:
        7 of them and filesize < 612352
}