rule win_nettraveler_auto {

    meta:
        atk_type = "win.nettraveler."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nettraveler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nettraveler"
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
        $sequence_0 = { ffd3 c70424???????? ff7508 a3???????? }
            // n = 4, score = 100
            //   ffd3                 | call                ebx
            //   c70424????????       |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   a3????????           |                     

        $sequence_1 = { 81ec8c000000 56 57 ff7508 8bf1 e8???????? 8bf8 }
            // n = 7, score = 100
            //   81ec8c000000         | sub                 esp, 0x8c
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_2 = { 83650800 83c70c 83c428 85ff 897df0 0f8eb6000000 bf00040000 }
            // n = 7, score = 100
            //   83650800             | and                 dword ptr [ebp + 8], 0
            //   83c70c               | add                 edi, 0xc
            //   83c428               | add                 esp, 0x28
            //   85ff                 | test                edi, edi
            //   897df0               | mov                 dword ptr [ebp - 0x10], edi
            //   0f8eb6000000         | jle                 0xbc
            //   bf00040000           | mov                 edi, 0x400

        $sequence_3 = { 53 68???????? ffd6 80a5dcf7ffff00 59 59 baff000000 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   80a5dcf7ffff00       | and                 byte ptr [ebp - 0x824], 0
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   baff000000           | mov                 edx, 0xff

        $sequence_4 = { 0bdf 33da 035dc4 8d9c18827e53f7 8bc3 c1e81a c1e306 }
            // n = 7, score = 100
            //   0bdf                 | or                  ebx, edi
            //   33da                 | xor                 ebx, edx
            //   035dc4               | add                 ebx, dword ptr [ebp - 0x3c]
            //   8d9c18827e53f7       | lea                 ebx, [eax + ebx - 0x8ac817e]
            //   8bc3                 | mov                 eax, ebx
            //   c1e81a               | shr                 eax, 0x1a
            //   c1e306               | shl                 ebx, 6

        $sequence_5 = { 0bd7 8b7dfc 0355e4 8dbc178a4c2a8d 8bd7 c1e214 c1ef0c }
            // n = 7, score = 100
            //   0bd7                 | or                  edx, edi
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   0355e4               | add                 edx, dword ptr [ebp - 0x1c]
            //   8dbc178a4c2a8d       | lea                 edi, [edi + edx - 0x72d5b376]
            //   8bd7                 | mov                 edx, edi
            //   c1e214               | shl                 edx, 0x14
            //   c1ef0c               | shr                 edi, 0xc

        $sequence_6 = { ff750c ff75d4 50 e8???????? 83c414 8945ec }
            // n = 6, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff75d4               | push                dword ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_7 = { e8???????? 83c418 8d45fc 897dfc 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   50                   | push                eax

        $sequence_8 = { ffd7 8945fc 8d4308 50 ffd7 8065e400 }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d4308               | lea                 eax, [ebx + 8]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8065e400             | and                 byte ptr [ebp - 0x1c], 0

        $sequence_9 = { 33df 035dc0 8d9c1992cc0c8f 8bcb c1e30a c1e916 0bcb }
            // n = 7, score = 100
            //   33df                 | xor                 ebx, edi
            //   035dc0               | add                 ebx, dword ptr [ebp - 0x40]
            //   8d9c1992cc0c8f       | lea                 ebx, [ecx + ebx - 0x70f3336e]
            //   8bcb                 | mov                 ecx, ebx
            //   c1e30a               | shl                 ebx, 0xa
            //   c1e916               | shr                 ecx, 0x16
            //   0bcb                 | or                  ecx, ebx

    condition:
        7 of them and filesize < 106496
}