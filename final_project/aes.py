'''
    Module which handles AES (Rijndael) Encryption 

    TODO: Make encryption and decryption more of a generic function, where we
    directly feed in the encryption functions

    Life saving source:
    https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns

    Verifying sources:
    https://www.cryptool.org/en/cto/aes-step-by-step
    https://www.simplilearn.com/tutorials/cryptography-tutorial/aes-encryption

'''
import secrets
PAD_BYTE = bytearray(1)[0]
ROUND_KEY_LENGTHS = {
    128 : (4, 11),
    192 : (6, 13),
    256 : (8, 15)
}
S_BOX = [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
            [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
            [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
            [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
        ]
INV_S_BOX = [
                [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
                [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
                [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
                [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
                [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
                [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
                [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
                [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
                [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
                [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
                [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
                [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
                [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
                [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
                [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
                [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
            ]
MULT_TABLE_9 = [
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
    0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
    0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
    0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
    0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
    0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
    0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
    0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
    0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
    0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
    0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
    0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
    0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
    0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
    0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
    0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
]
MULT_TABLE_11 = [
    0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
    0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
    0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
    0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
    0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
    0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
    0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
    0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
    0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
    0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
    0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
    0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
    0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
    0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
    0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
    0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
]
MULT_TABLE_13 = [
    0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
    0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
    0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
    0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
    0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
    0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
    0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
    0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
    0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
    0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
    0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
    0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
    0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
    0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
    0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
    0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
]
MULT_TABLE_14 = [
    0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
    0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
    0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
    0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
    0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
    0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
    0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
    0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
    0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
    0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
    0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
    0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
    0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
    0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
    0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
    0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
]
MIX_MATRIX = [
                [2, 3, 1, 1],
                [1, 2, 3, 1],
                [1, 1, 2, 3],
                [3, 1, 1, 2]
            ]
INV_MIX_MATRIX = [
                    [14, 11, 13,  9],
                    [ 9, 14, 11, 13],
                    [13,  9, 14, 11],
                    [11, 13,  9, 14]
                ]
INV_MULT_LOOKUP = {
    9 : MULT_TABLE_9,
    11: MULT_TABLE_11,
    13: MULT_TABLE_13,
    14: MULT_TABLE_14
}
ROUND_CONSTANTS = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def bytearray_to_bitarray(array):
    '''
        Function
    '''
    bitarray = []
    for byte in array:
        # Convert byte into string
        byte_string = f"{byte:08b}"
        for bit in byte_string:
            bitarray.append(int(bit))
    return bitarray

def bitarray_to_matrix(plaintext):
    '''
        Function which converts a plaintext represented in 128-bit into a matrix
        of 16 bytes
    '''
    matrix = [
        [],
        [],
        [],
        []
    ]
    for i in range(len(plaintext) // 8):
        matrix[i % 4].append(plaintext[i * 8 : (i + 1) * 8])
    return matrix

def matrix_to_hexstring(matrix):
    '''
        Function which converts a matrix into a hexstring
    '''
    string = ""
    for k in range(4):
        for j in range(4):
            string += f"{bitarray_to_int(matrix[j][k]):02x}"
    return string

def bitarray_to_int(bitarray):
    '''
        Function which transforms a bitarray to its integer equivalent
    '''
    return int(''.join([str(b) for b in bitarray]), 2)

def int_to_bitarray(integer, bits):
    '''
        Function which transforms an integer into a bitarray with <bits> length
    '''
    return [int(i) for i in f"{integer:0{bits}b}"]

def rotate_array(array, n):
    '''
        Function which circularly rotates an array to the left <n> times
    
    '''
    for i in range(n):
        array = array[8:] + array[:8]
    return array

def do_xor(bitarray1, bitarray2):
    '''
        Function which takes two bit arrays and XORs them
    '''
    result = []
    for i, bit in enumerate(bitarray1):
        result.append(bit ^ bitarray2[i])
    return result

def substitute_byte(byte, inverse=False):
    byte = ''.join([str(b) for b in byte])
    first_half = int(byte[:4], 2)
    second_half = int(byte[4:], 2)
    if inverse:
        return f"{INV_S_BOX[first_half][second_half]:08b}"
    return f"{S_BOX[first_half][second_half]:08b}"

def substitute_word(word):
    bytes = [word[i * 8 : (i + 1) * 8] for i in range(4)]
    result = []
    for byte in bytes:
        result += [int(b) for b in substitute_byte(byte)]
    return result

def do_ECB(block, key, IV, *args, decrypt=False):
    '''
        Function which handles ECB encryption/decryption
    '''
    if not decrypt:
        outputblock = do_aes(block, key)
    else:
        outputblock = undo_aes(block, key)
    IV = bytearray_to_bitarray(bytearray.fromhex(outputblock))
    return outputblock, IV

def do_CBC(block, key, IV, *args, decrypt=False):
    '''
        Function which handles CBC encryption/decryption
    '''
    # CBC handling for encryption
    if not decrypt:
        block = do_xor(block, IV)
        outputblock = do_aes(block, key)
        IV = bytearray_to_bitarray(bytearray.fromhex(outputblock))
    else:
        # CBC handling for decryption
        outputblock = undo_aes(block, key)
        outputblock = bytearray_to_bitarray(bytearray.fromhex(outputblock))
        outputblock = do_xor(IV, outputblock)
        outputblock = f"{bitarray_to_int(outputblock):02x}"
        if len(outputblock) != 32:
            outputblock = (32 - len(outputblock)) * '0' + outputblock
        IV = block
    return outputblock, IV

def do_PCBC(block, key, IV, counter, decrypt=False):
    '''
        Function which handles PCBC encryption/decryption
    '''
    original = block

    # PCBC handling for encryption
    if not decrypt:
        block = do_xor(block, IV)
        outputblock = do_aes(block, key)
    else:
        # PCBC handling for decryption
        outputblock = undo_aes(block, key)
        outputblock = bytearray_to_bitarray(bytearray.fromhex(outputblock))
        outputblock = do_xor(IV, outputblock)
        outputblock = f"{bitarray_to_int(outputblock):02x}"
        if len(outputblock) != 32:
            outputblock = (32 - len(outputblock)) * '0' + outputblock
    IV = do_xor(original, bytearray_to_bitarray(bytearray.fromhex(outputblock)))
    return outputblock, IV

def do_CTR(block, key, IV, counter, decrypt=False):
    '''
        Function which handles CTR encryption/decryption
    '''
    nonce = do_xor(IV, int_to_bitarray(counter, 128))
    outputblock = do_aes(nonce, key)
    outputblock = bytearray_to_bitarray(bytearray.fromhex(outputblock))
    outputblock = do_xor(outputblock, block)
    outputblock = f"{bitarray_to_int(outputblock):02x}"
    if len(outputblock) != 32:
        outputblock = (32 - len(outputblock)) * '0' + outputblock
    return outputblock, IV

def do_CFB(block, key, IV, *args, decrypt=False):
    '''
        Function which handles CFB encryption/decryption
    '''
    outputblock = do_aes(IV, key)
    outputblock = bytearray_to_bitarray(bytearray.fromhex(outputblock))
    outputblock = do_xor(outputblock, block)
    if decrypt:
        IV = block
    else:
        IV = outputblock
    outputblock = f"{bitarray_to_int(outputblock):02x}"
    if len(outputblock) != 32:
        outputblock = (32 - len(outputblock)) * '0' + outputblock
    return outputblock, IV

def do_OFB(block, key, IV, *args, decrypt=False):
    '''
        Function which handles OFB encryption/decryption
    '''
    outputblock = do_aes(IV, key)
    outputblock = bytearray_to_bitarray(bytearray.fromhex(outputblock))
    IV = outputblock
    outputblock = do_xor(outputblock, block)
    outputblock = f"{bitarray_to_int(outputblock):02x}"
    if len(outputblock) != 32:
        outputblock = (32 - len(outputblock)) * '0' + outputblock
    return outputblock, IV


MODES = {
    "ECB" : do_ECB,
    "CBC" : do_CBC,
    "PCBC" : do_PCBC,
    "CTR" : do_CTR,
    "CFB" : do_CFB,
    "OFB" : do_OFB
}

def aes_encrypt(plaintext, key=None, mode="ECB", IV=None, ransom=False):
    '''
        Function which encrypts a plaintext using the AES algorithm.

        Inputs:
            plaintext   (str)    - String which is to be encrypted. Is converted
                                    to unicode
            key         (str)    - 128/192/256-bit hexadecimal string used to encrypt the
                                    plaintext. If none is given, one is generated
                                    (defaulted at 128-bits)
            mode        (str)    - One of three modes (ECB, CBC, CTR). Default is
                                    ECB
            IV          (str)    - 128-bit hexadecimal string that must be given if
                                    mode is CBC or CTR
        Returns:
            cipher_hex  (str)    - The ciphertext in a hexadecimal string
            key         (str)    - The key used as a hexadecimal string
            IV          (str)    - The initialisation vector used, as a hexadecimal
                                    string. Is None if no IV given
    '''
    if ransom:
        plaintext_bytes = plaintext
    else:
        plaintext_bytes = bytearray(plaintext, 'utf-8')
    initial_IV = IV
    key_length = 0

    # Handle key generation
    if not key:
        key = bytearray(secrets.token_bytes(16))    # 128-bits
        key_length = 32
    else:
        key_length = len(key)
        # Convert key hexadecimal to binary bytes
        key = bytearray.fromhex(key)
    key = bytearray_to_bitarray(key)

    if not IV:
        IV = bytearray(secrets.token_bytes(16))     # 128-bits
    else:
        # Convert IV hexadeimal to binary bytes
        IV = bytearray.fromhex(IV)
    IV = bytearray_to_bitarray(IV)
    initial_IV = IV

    # Handle padding
    to_pad = 128
    plaintext_bits = len(plaintext_bytes) * 8
    if plaintext_bits % 128 != 0:
        to_pad = (plaintext_bits // 128 + 1) * 128 - plaintext_bits
    for i in range((to_pad // 8) - 1):
        plaintext_bytes.append(PAD_BYTE)
    plaintext_bytes.append(to_pad // 8)
    plaintext_bytes = bytearray_to_bitarray(plaintext_bytes)
    
    # Encrypt plaintext in 128-bit blocks
    ciphertext = ""
    for i in range(len(plaintext_bytes) // 128):
        plaintext_block = plaintext_bytes[i * 128 : (i + 1) * 128]
        cipherblock, IV = MODES[mode](plaintext_block, key, IV, i, decrypt=False)
        ciphertext += cipherblock
    key = f"{bitarray_to_int(key):02x}"
    if len(key) != key_length:
        key = (key_length - len(key)) * "0" + key
    # print(key)
    initial_IV = f"{bitarray_to_int(initial_IV):02x}"
    if len(initial_IV) != 32:
        initial_IV = (32 - len(initial_IV)) * "0" + initial_IV
    return ciphertext, key, initial_IV

def aes_decrypt(ciphertext, key, mode="ECB", IV=None, ransom=False):
    '''
        Function which decrypts a ciphertext using the AES algorithm.

        Inputs:
            plaintext   (str)    - String which is to be encrypted. Is converted
                                    to unicode
            key         (str)    - 64-bit hexadecimal string used to encrypt the
                                    plaintext.
            mode        (str)    - One of three modes (ECB, CBC, CTR). Default is
                                    ECB
            IV          (str)    - 64-bit hexadecimal string that must be given if
                                    mode is CBC or CTR.
        Returns:
            plaintext   (str)    - The plaintext in unicode
    '''
    plaintext = ""

    # Unpack output data
    if ransom:
        cipher_bytes = ciphertext
    else:
        cipher_bytes = bytearray.fromhex(ciphertext)
    cipher_bits = bytearray_to_bitarray(cipher_bytes)
    key = bytearray_to_bitarray(bytearray.fromhex(key))
    if IV:
        IV = bytearray_to_bitarray(bytearray.fromhex(IV))

    for i in range(len(cipher_bits) // 128):
        cipher_block = cipher_bits[i * 128 : (i + 1) * 128]
        plainblock, IV = MODES[mode](cipher_block, key, IV, i, decrypt=True)
        plaintext += plainblock

    # Strip padding
    to_remove = int(plaintext[-2:], 16) * 2
    plaintext = plaintext[:-to_remove]
    plaintext_int = int(plaintext, 16)
    if not ransom:
        return plaintext_int.to_bytes((len(plaintext) * 4) // 8, byteorder='big').decode('utf-8').rstrip('\x00')
    else:
        return plaintext_int.to_bytes((len(plaintext) * 4) // 8, byteorder='big')

def generate_round_keys(key):
    '''
        Function which generates round keys for AES
    '''

    expanded_keywords = []

    # Separate the key into 32-bit words
    key_length = len(key)
    round_key_length, rounds = ROUND_KEY_LENGTHS[key_length]
    key_words = [key[32 * i : 32 * (i + 1)] for i in range(round_key_length)]

    # Generate expanded key
    for i in range(4 * rounds):
        if i < round_key_length:
            expanded_keywords.append(key_words[i])
        elif i >= round_key_length and i % round_key_length == 0:
            component_1 = expanded_keywords[i - round_key_length]
            component_2 = substitute_word(rotate_array(expanded_keywords[i - 1], 1))
            rcon = (f"{ROUND_CONSTANTS[i // round_key_length - 1]:08b}" + "0" * 24)
            word = int(''.join([str(b) for b in component_1]), 2) ^ int(''.join([str(b) for b in component_2]), 2) ^ int(rcon, 2)
            word = [int(b) for b in f"{word:032b}"]
            expanded_keywords.append(word)
        elif i >= round_key_length and round_key_length > 6 and i % round_key_length == 4:
            component_1 = expanded_keywords[i - round_key_length]
            component_2 = substitute_word(expanded_keywords[i - 1])
            word = int(''.join([str(b) for b in component_1]), 2) ^ int(''.join([str(b) for b in component_2]), 2)
            expanded_keywords.append([int(b) for b in f"{word:032b}"])
        else:
            word = int(''.join([str(b) for b in expanded_keywords[i - round_key_length]]), 2) ^ int(''.join([str(b) for b in expanded_keywords[i - 1]]), 2)
            expanded_keywords.append([int(b) for b in f"{word:032b}"])

    keys = ''.join([''.join([str(k) for k in b]) for b in expanded_keywords])
    return  [keys[128 * i : (i + 1) * 128] for i in range(rounds)]

def add_round_key(matrix, round_key):
    '''
        Function which XORs the round key and the given matrix
    '''
    for r, row in enumerate(matrix):
        for c, col in enumerate(row):
            # Transform bitarrays into int and XOR
            entry = bitarray_to_int(col) ^ bitarray_to_int(round_key[r][c])
            # print(f"{bitarray_to_int(col):0x} XOR {bitarray_to_int(round_key[r][c]):0x} = {entry:0x}")
            matrix[r][c] = int_to_bitarray(entry, 8)
    return matrix

def do_s_box(matrix, inverse=False):
    '''
        Function which applies the SBOX substitution on the given matrix
    '''
    for r, row in enumerate(matrix):
        for c, cell in enumerate(row):
            matrix[r][c] = substitute_byte(cell, inverse)
    return matrix

def shift_rows(matrix, inverse=False):
    '''
        Function which shifts the rows of the matrix by index - 1 places to the
        left.
    '''
    for r, row in enumerate(matrix):
        for i in range(r):
            if inverse:
                matrix[r] = matrix[r][-1:] + matrix[r][:-1]
            else:
                matrix[r] = matrix[r][1:] + matrix[r][:1]
    return matrix

def bit_mult(num, bitarray):
    '''
        Function which handles bit multiplication
    '''
    if num == 1:
        return bitarray_to_int(bitarray)
    else:
        result = bitarray_to_int(bitarray) << 1
        if bitarray[0] == '1':
            result = result ^ 27
        if num == 3:
            result ^= bitarray_to_int(bitarray)
        return result

def mix_columns(matrix):
    '''
        Function which mixes the columns of the given matrix by the constant AES
        matrix
    '''
    new_matrix = [
        [],
        [],
        [],
        []
    ]
    for col in range(4):
        d0 =    bit_mult(MIX_MATRIX[0][0], matrix[0][col]) ^ \
                bit_mult(MIX_MATRIX[0][1], matrix[1][col]) ^ \
                bit_mult(MIX_MATRIX[0][2], matrix[2][col]) ^ \
                bit_mult(MIX_MATRIX[0][3], matrix[3][col])

        d1 =    bit_mult(MIX_MATRIX[1][0], matrix[0][col]) ^ \
                bit_mult(MIX_MATRIX[1][1], matrix[1][col]) ^ \
                bit_mult(MIX_MATRIX[1][2], matrix[2][col]) ^ \
                bit_mult(MIX_MATRIX[1][3], matrix[3][col])

        d2 =    bit_mult(MIX_MATRIX[2][0], matrix[0][col]) ^ \
                bit_mult(MIX_MATRIX[2][1], matrix[1][col]) ^ \
                bit_mult(MIX_MATRIX[2][2], matrix[2][col]) ^ \
                bit_mult(MIX_MATRIX[2][3], matrix[3][col])

        d3 =    bit_mult(MIX_MATRIX[3][0], matrix[0][col]) ^ \
                bit_mult(MIX_MATRIX[3][1], matrix[1][col]) ^ \
                bit_mult(MIX_MATRIX[3][2], matrix[2][col]) ^ \
                bit_mult(MIX_MATRIX[3][3], matrix[3][col])

        new_matrix[0].append(int_to_bitarray(d0 % 256, 8))
        new_matrix[1].append(int_to_bitarray(d1 % 256, 8))
        new_matrix[2].append(int_to_bitarray(d2 % 256, 8))
        new_matrix[3].append(int_to_bitarray(d3 % 256, 8))
    return new_matrix

def inv_mix_columns(matrix):
    '''
        Function which inverse mixes the columns as part of the decryption process
    '''
    new_matrix = [
        [],
        [],
        [],
        []
    ]
    for col in range(4):
        d0 =    INV_MULT_LOOKUP[INV_MIX_MATRIX[0][0]][bitarray_to_int(matrix[0][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[0][1]][bitarray_to_int(matrix[1][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[0][2]][bitarray_to_int(matrix[2][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[0][3]][bitarray_to_int(matrix[3][col])]

        d1 =    INV_MULT_LOOKUP[INV_MIX_MATRIX[1][0]][bitarray_to_int(matrix[0][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[1][1]][bitarray_to_int(matrix[1][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[1][2]][bitarray_to_int(matrix[2][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[1][3]][bitarray_to_int(matrix[3][col])]

        d2 =    INV_MULT_LOOKUP[INV_MIX_MATRIX[2][0]][bitarray_to_int(matrix[0][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[2][1]][bitarray_to_int(matrix[1][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[2][2]][bitarray_to_int(matrix[2][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[2][3]][bitarray_to_int(matrix[3][col])]

        d3 =    INV_MULT_LOOKUP[INV_MIX_MATRIX[3][0]][bitarray_to_int(matrix[0][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[3][1]][bitarray_to_int(matrix[1][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[3][2]][bitarray_to_int(matrix[2][col])] ^ \
                INV_MULT_LOOKUP[INV_MIX_MATRIX[3][3]][bitarray_to_int(matrix[3][col])]

        new_matrix[0].append(int_to_bitarray(d0 % 256, 8))
        new_matrix[1].append(int_to_bitarray(d1 % 256, 8))
        new_matrix[2].append(int_to_bitarray(d2 % 256, 8))
        new_matrix[3].append(int_to_bitarray(d3 % 256, 8))
    return new_matrix

def inverse_round_keys(round_keys):
    '''
        Function which inverst the round keys with inv_mix_column
    '''
    new_keys = []
    new_keys.append(round_keys[0])
    for i in range(1, len(round_keys) - 1):
        inverted_key = inv_mix_columns(bitarray_to_matrix(round_keys[i]))
        inverted_key = bytearray_to_bitarray(bytearray.fromhex(matrix_to_hexstring(inverted_key)))
        new_keys.append(inverted_key)
    new_keys.append(round_keys[-1])
    return new_keys

def do_aes(plaintext, key, *args):
    '''
        Function which actually does this AES encryption process
    '''
    matrix = bitarray_to_matrix(plaintext)
    round_keys = generate_round_keys(key)
    key_length = len(key)
    rounds = ROUND_KEY_LENGTHS[key_length][1]

    # Initial transformation
    round_key = bitarray_to_matrix(round_keys[0])
    state = add_round_key(matrix, round_key)
    # For Each Round
    for i in range(rounds - 2):
        # S_BOX substitution
        state = do_s_box(state)
        # for i in state:
        #     for j in i:
        #         print(f"{bitarray_to_int(j):02x}", end=' ')
        #     print()
        # print("-------------------------------------------------------------")
        # Shift rows
        state = shift_rows(state)
        # for i in state:
        #     for j in i:
        #         print(f"{bitarray_to_int(j):02x}", end=' ')
        #     print()
        # print("-------------------------------------------------------------")
        # Mix Columns
        state = mix_columns(state)
        # for i in state:
        #     for j in i:
        #         print(f"{bitarray_to_int(j):02x}", end=' ')
        #     print()
        # print("-------------------------------------------------------------")
        # Add round key
        state = add_round_key(state, bitarray_to_matrix(round_keys[i + 1]))
    
    # Final round
    # S_BOX substitution
    state = do_s_box(state)

    # Shift rows
    state = shift_rows(state)

    # Add round key
    state = add_round_key(state, bitarray_to_matrix(round_keys[i + 2]))
    # for k in state:
    #     for j in k:
    #         print(f"{bitarray_to_int(j):02x}", end=' ')
    #     print()
    return matrix_to_hexstring(state)

def undo_aes(ciphertext, key, *args):
    '''
        Function which actually does the AES unencryption process
    '''
    matrix = bitarray_to_matrix(ciphertext)
    round_keys = inverse_round_keys(generate_round_keys(key))
    key_length = len(key)
    rounds = ROUND_KEY_LENGTHS[key_length][1]

    # Initial transformation
    round_key = bitarray_to_matrix(round_keys[rounds - 1])
    state = add_round_key(matrix, round_key)
    # for i in state:
    #     for j in i:
    #         print(f"{bitarray_to_int(j):02x}", end=' ')
    #     print()
    # print("-------------------------------------------------------------")

    # For Each Round
    for k in range(rounds - 2):
        # print(f"Round {k}:")
        # S_BOX substitution
        state = do_s_box(state, inverse=True)
        # for i in state:
        #     for j in i:
        #         print(f"{bitarray_to_int(j):02x}", end=' ')
        #     print()
        # print("-------------------------------------------------------------")
        # # Shift rows
        state = shift_rows(state, inverse=True)
        # for i in state:
        #     for j in i:
        #         print(f"{bitarray_to_int(j):02x}", end=' ')
        #     print()
        # print("-------------------------------------------------------------")
        # Mix Columns
        state = inv_mix_columns(state)
        # for i in state:
        #     for j in i:
        #         print(f"{bitarray_to_int(j):02x}", end=' ')
        #     print()
        # print("-------------------------------------------------------------")
        # Add round key
        state = add_round_key(state, bitarray_to_matrix(round_keys[rounds - 2 - k]))
    
    # Final round
    # S_BOX substitution
    state = do_s_box(state, inverse=True)

    # Shift rows
    state = shift_rows(state, inverse=True)

    # Add round key
    state = add_round_key(state, bitarray_to_matrix(round_keys[0]))
    # for k in state:
    #     for j in k:
    #         print(f"{bitarray_to_int(j):02x}", end=' ')
    #     print()
    return matrix_to_hexstring(state)


if __name__ == "__main__":
    # Testing ECB
    cipher, key, iv = aes_encrypt("This is an ECB coded message | 这是一条 ECB 编码的消息 | هذه رسالة مشفرة في ECB", mode="ECB")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = aes_decrypt(cipher, key, mode="ECB", IV=iv).rstrip()
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This is an ECB coded message | 这是一条 ECB 编码的消息 | هذه رسالة مشفرة في ECB"

    # Testing CBC
    cipher, key, iv = aes_encrypt("This message is coded with CBC | هذه الرسالة مشفرة بواسطة CBC | 此消息使用 CBC 編碼", mode="CBC")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = aes_decrypt(cipher, key, mode="CBC", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with CBC | هذه الرسالة مشفرة بواسطة CBC | 此消息使用 CBC 編碼"

    # Testing CTR
    cipher, key, iv = aes_encrypt("此消息由 CTR 加密 | This message is encrypted by CTR | تم تشفير هذه الرسالة بواسطة نسبة النقر إلى الظهور (CTR)", mode="CTR")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = aes_decrypt(cipher, key, mode="CTR", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "此消息由 CTR 加密 | This message is encrypted by CTR | تم تشفير هذه الرسالة بواسطة نسبة النقر إلى الظهور (CTR)"

    # Testing PCBC
    cipher, key, iv = aes_encrypt("This message is coded with PCBC | هذه الرسالة مشفرة بواسطة PCBC | 此消息使用 PCBC 編碼", mode="PCBC")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = aes_decrypt(cipher, key, mode="PCBC", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with PCBC | هذه الرسالة مشفرة بواسطة PCBC | 此消息使用 PCBC 編碼"

    # Testing CFB
    cipher, key, iv = aes_encrypt("This message is coded with CFB | هذه الرسالة مشفرة بواسطة CFB | 此消息使用 CFB 編碼", mode="CFB")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = aes_decrypt(cipher, key, mode="CFB", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with CFB | هذه الرسالة مشفرة بواسطة CFB | 此消息使用 CFB 編碼"

    # Testing OFB
    cipher, key, iv = aes_encrypt("This message is coded with OFB | هذه الرسالة مشفرة بواسطة OFB | 此消息使用 OFB 編碼", mode="OFB")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = aes_decrypt(cipher, key, mode="OFB", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with OFB | هذه الرسالة مشفرة بواسطة OFB | 此消息使用 OFB 編碼"


    print("=====================================================================")
    ciphertext, key, IV = aes_encrypt("你好，这个加密文本来自法律讲座", mode="CBC")
    print(f"Your encrypted text is: {ciphertext}\nYour key is: {key} - don't lose this!\nYour IV is: {IV}")
    plaintext = aes_decrypt(ciphertext, key=key, mode="CBC", IV=IV)
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "你好，这个加密文本来自法律讲座"
    print("=====================================================================")

    # Stress test reliability ECB:
    print(f"Testing ECB Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting ECB Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = aes_encrypt("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="ECB")
        plaintext = aes_decrypt(cipher, key, mode="ECB", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    # Stress test reliability CBC:
    print(f"Testing CBC Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting CBC Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = aes_encrypt("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="CBC")
        plaintext = aes_decrypt(cipher, key, mode="CBC", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    # Stress test reliability CTR:
    print(f"Testing CTR Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting CTR Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = aes_encrypt("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="CTR")
        plaintext = aes_decrypt(cipher, key, mode="CTR", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    # Stress test reliability PCBC:
    print(f"Testing PCBC Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting PCBC Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = aes_encrypt("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="PCBC")
        plaintext = aes_decrypt(cipher, key, mode="PCBC", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    # Stress test reliability CFB:
    print(f"Testing PCBC Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting CFB Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = aes_encrypt("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="CFB")
        plaintext = aes_decrypt(cipher, key, mode="CFB", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    # Stress test reliability OFB:
    print(f"Testing OFB Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting OFB Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = aes_encrypt("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="OFB")
        plaintext = aes_decrypt(cipher, key, mode="OFB", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    print("\nTesting complete! Everything's functional!")
