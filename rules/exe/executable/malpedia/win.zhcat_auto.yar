rule win_zhcat_auto {

    meta:
        atk_type = "win.zhcat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.zhcat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zhcat"
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
        $sequence_0 = { 8b3d???????? 8b7508 4f 8945fc }
            // n = 4, score = 200
            //   8b3d????????         |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   4f                   | dec                 edi
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_1 = { 741e 8d45f8 8975f8 50 85ff 750a }
            // n = 6, score = 200
            //   741e                 | je                  0x20
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   50                   | push                eax
            //   85ff                 | test                edi, edi
            //   750a                 | jne                 0xc

        $sequence_2 = { 85c9 759e 56 e8???????? 59 }
            // n = 5, score = 200
            //   85c9                 | test                ecx, ecx
            //   759e                 | jne                 0xffffffa0
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_3 = { 85c9 759e 56 e8???????? 59 5f 5e }
            // n = 7, score = 200
            //   85c9                 | test                ecx, ecx
            //   759e                 | jne                 0xffffffa0
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { 3c74 7404 3c54 7512 8915???????? eb0a }
            // n = 6, score = 200
            //   3c74                 | cmp                 al, 0x74
            //   7404                 | je                  6
            //   3c54                 | cmp                 al, 0x54
            //   7512                 | jne                 0x14
            //   8915????????         |                     
            //   eb0a                 | jmp                 0xc

        $sequence_5 = { 68???????? 56 56 897004 ffd3 6aff }
            // n = 6, score = 200
            //   68????????           |                     
            //   56                   | push                esi
            //   56                   | push                esi
            //   897004               | mov                 dword ptr [eax + 4], esi
            //   ffd3                 | call                ebx
            //   6aff                 | push                -1

        $sequence_6 = { ff7508 ff15???????? ff7514 8945e4 8bc7 668945f0 ffd6 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8bc7                 | mov                 eax, edi
            //   668945f0             | mov                 word ptr [ebp - 0x10], ax
            //   ffd6                 | call                esi

        $sequence_7 = { eb28 c705????????02000000 eb1c c605????????01 }
            // n = 4, score = 200
            //   eb28                 | jmp                 0x2a
            //   c705????????02000000     |     
            //   eb1c                 | jmp                 0x1e
            //   c605????????01       |                     

        $sequence_8 = { 0fb63e 0fb6c0 eb12 8b45e0 8a80044a4100 08443b1d 0fb64601 }
            // n = 7, score = 200
            //   0fb63e               | movzx               edi, byte ptr [esi]
            //   0fb6c0               | movzx               eax, al
            //   eb12                 | jmp                 0x14
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8a80044a4100         | mov                 al, byte ptr [eax + 0x414a04]
            //   08443b1d             | or                  byte ptr [ebx + edi + 0x1d], al
            //   0fb64601             | movzx               eax, byte ptr [esi + 1]

        $sequence_9 = { ff7508 ff15???????? 57 8bf0 e8???????? 59 5f }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   57                   | push                edi
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 376832
}