rule win_tinba_auto {

    meta:
        atk_type = "win.tinba."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.tinba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinba"
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
        $sequence_0 = { 8b7508 ad 50 56 }
            // n = 4, score = 1100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_1 = { 8b4510 aa 8b450c ab }
            // n = 4, score = 1100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_2 = { 8a241f 88240f 88041f 41 }
            // n = 4, score = 1000
            //   8a241f               | mov                 ah, byte ptr [edi + ebx]
            //   88240f               | mov                 byte ptr [edi + ecx], ah
            //   88041f               | mov                 byte ptr [edi + ebx], al
            //   41                   | inc                 ecx

        $sequence_3 = { 6a00 6a00 6a00 ff750c 6a00 6a00 ff7508 }
            // n = 7, score = 1000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_4 = { 8b4114 83f8fd 7506 8b4108 8b4014 85c0 7403 }
            // n = 7, score = 900
            //   8b4114               | mov                 eax, dword ptr [ecx + 0x14]
            //   83f8fd               | cmp                 eax, -3
            //   7506                 | jne                 8
            //   8b4108               | mov                 eax, dword ptr [ecx + 8]
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_5 = { 66b80d0a 66ab b8436f6f6b ab b869653a20 ab }
            // n = 6, score = 900
            //   66b80d0a             | mov                 ax, 0xa0d
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   b8436f6f6b           | mov                 eax, 0x6b6f6f43
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   b869653a20           | mov                 eax, 0x203a6569
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_6 = { ff15???????? 48 83c420 48 85c0 0f84b4000000 }
            // n = 6, score = 900
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   83c420               | add                 esp, 0x20
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   0f84b4000000         | je                  0xba

        $sequence_7 = { 814a3500080000 4c 29c6 40 8832 }
            // n = 5, score = 900
            //   814a3500080000       | or                  dword ptr [edx + 0x35], 0x800
            //   4c                   | dec                 esp
            //   29c6                 | sub                 esi, eax
            //   40                   | inc                 eax
            //   8832                 | mov                 byte ptr [edx], dh

        $sequence_8 = { 8b7d0c 31c9 bb0a000000 31d2 f7f3 52 }
            // n = 6, score = 900
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   31c9                 | xor                 ecx, ecx
            //   bb0a000000           | mov                 ebx, 0xa
            //   31d2                 | xor                 edx, edx
            //   f7f3                 | div                 ebx
            //   52                   | push                edx

        $sequence_9 = { 8b4514 8908 290e 8b06 }
            // n = 4, score = 900
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   290e                 | sub                 dword ptr [esi], ecx
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_10 = { 66b80d0a 66ab b855736572 ab b82d416765 ab }
            // n = 6, score = 900
            //   66b80d0a             | mov                 ax, 0xa0d
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   b855736572           | mov                 eax, 0x72657355
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   b82d416765           | mov                 eax, 0x6567412d
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_11 = { 73ed 88e8 48 8d1d5a020000 }
            // n = 4, score = 900
            //   73ed                 | jae                 0xffffffef
            //   88e8                 | mov                 al, ch
            //   48                   | dec                 eax
            //   8d1d5a020000         | lea                 ebx, [0x25a]

        $sequence_12 = { fd 8b7d0c 83c707 8b4508 83e00f }
            // n = 5, score = 900
            //   fd                   | std                 
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   83c707               | add                 edi, 7
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83e00f               | and                 eax, 0xf

    condition:
        7 of them and filesize < 57344
}