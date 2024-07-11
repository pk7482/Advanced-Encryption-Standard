// AES-128(Key Size is 128 bits)
// We will have 10 rounds
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <bits/stdc++.h>
using namespace std;

// Variables of Global Use
// Initializing S_Box
int S_box[256] = {
    // 0     1     2     3     4     5     6     7
    // 8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x21, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F
// Inverse S_Box for decryption
int inv_S_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
// To Store all ROound Keys
int RoundKeys[11][4][4];

KhushiTapariya, [11-07-2024 10:40]
// Key Exapnsion Function
void Key_Expansion(int Keys[4][4], int Round)
{
    int S_boxed_current_word[4], temp;
    int RCKey[4] = {Round, 0x00, 0x00, 0x00};
    int g_Func_Key[4];
    //-----------g-function---------------------
    for (int i = 0; i < 4; i++)
    {
        g_Func_Key[i] = Keys[3][i];
    }
    // One Byte left circuilar shift
    temp = g_Func_Key[0];
    g_Func_Key[0] = g_Func_Key[1];
    g_Func_Key[1] = g_Func_Key[2];
    g_Func_Key[2] = g_Func_Key[3];
    g_Func_Key[3] = temp;

    // S-box Use
    for (int j = 0; j < 4; j++)
        S_boxed_current_word[j] = S_box[g_Func_Key[j]];

    // XOR with RC word
    for (int j = 0; j < 4; j++)
    {
        S_boxed_current_word[j] ^= RCKey[j];
        g_Func_Key[j] = S_boxed_current_word[j];
    }

    // Finalizing Keys
    for (int i = 0; i < 4; i++)
    {
        // XOR with next index(previous)
        for (int j = 0; j < 4; j++)
        {
            if (i == 0)
                Keys[i][j] ^= g_Func_Key[j];
            else
                Keys[i][j] ^= Keys[i - 1][j];
        }
    }
}

// Add Round Key
void addRoundKey(unsigned char Plain_Text[4][4], int Keys[4][4])
{
    // bitwise XOR with Keys(words)
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Plain_Text[i][j] ^= Keys[i][j];
}
//--------------Encrypting Transformations---------------------
// Substitute Bytes from S_Box
void substituteBytes(unsigned char Cipher_Text[4][4])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Cipher_Text[i][j] = S_box[Cipher_Text[i][j]];
}
// Shift Rounds
void shiftRows(unsigned char Cipher_Text[4][4])
{
    //------------Shifting in 2nd Row-------------
    int temp = Cipher_Text[0][1];
    Cipher_Text[0][1] = Cipher_Text[1][1];
    Cipher_Text[1][1] = Cipher_Text[2][1];
    Cipher_Text[2][1] = Cipher_Text[3][1];
    Cipher_Text[3][1] = temp;

    //------------Shifting in 3rd Row------------
    swap(Cipher_Text[0][2], Cipher_Text[2][2]);
    swap(Cipher_Text[1][2], Cipher_Text[3][2]);

    //------------Shifting in 4th Row------------
    temp = Cipher_Text[3][3];
    Cipher_Text[3][3] = Cipher_Text[2][3];
    Cipher_Text[2][3] = Cipher_Text[1][3];
    Cipher_Text[1][3] = Cipher_Text[0][3];
    Cipher_Text[0][3] = temp;
}
// Galois Multiplication for column mixing
unsigned char galois_multiplication(unsigned char a, unsigned char b)
{
    unsigned char mul = 0;
    bool hi_bit;
    for (int i = 0; i < 8; i++)
    {
        if (b & 0x01)
            mul ^= a;
        hi_bit = (a & 0x80);
        a <<= 1;
        if (hi_bit)
            a ^= 0x1b;
        b >>= 1;
    }
    return mul;
}
// Mixing Columns Transformation
void mixColumns(unsigned char Cipher_Text[4][4])
{
    // Output matrix after mixing
    unsigned char Output_Matrix[4][4];
    // Assigning Initial Valie to zero
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Output_Matrix[i][j] = 0x00;

    // Initializing Matrix to be galois multiplied
    unsigned char Multiplication_Matrix[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                                 {0x01, 0x02, 0x03, 0x01},
                                                 {0x01, 0x01, 0x02, 0x03},
                                                 {0x03, 0x01, 0x01, 0x02}};
    // Multiplying and taking XOR
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Output_Matrix[j][i] = (galois_multiplication(Multiplication_Matrix[i][0], Cipher_Text[j][0]) ^
                                   galois_multiplication(Multiplication_Matrix[i][1], Cipher_Text[j][1])) ^
                                  (galois_multiplication(Multiplication_Matrix[i][2], Cipher_Text[j][2]) ^
                                   galois_multiplication(Multiplication_Matrix[i][3], Cipher_Text[j][3]));
    // Returning Value
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Cipher_Text[i][j] = Output_Matrix[i][j];
}

KhushiTapariya, [11-07-2024 10:40]
//----------------------------Decrypting Transformations---------------------
// Inverse Substitute Bytes from inverse S)box
void invSubstituteBytes(unsigned char Cipher_Text[4][4])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Cipher_Text[i][j] = inv_S_box[Cipher_Text[i][j]];
}
// Inverse Shift Rounds
void InvShiftRows(unsigned char Cipher_Text[4][4])
{
    //------------Shifting in 2nd Row------------
    unsigned char temp = Cipher_Text[3][1];
    Cipher_Text[3][1] = Cipher_Text[2][1];
    Cipher_Text[2][1] = Cipher_Text[1][1];
    Cipher_Text[1][1] = Cipher_Text[0][1];
    Cipher_Text[0][1] = temp;

    //------------Shifting in 3rd Row------------
    swap(Cipher_Text[0][2], Cipher_Text[2][2]);
    swap(Cipher_Text[1][2], Cipher_Text[3][2]);

    //------------Shifting in 4th Row-------------
    temp = Cipher_Text[0][3];
    Cipher_Text[0][3] = Cipher_Text[1][3];
    Cipher_Text[1][3] = Cipher_Text[2][3];
    Cipher_Text[2][3] = Cipher_Text[3][3];
    Cipher_Text[3][3] = temp;
}
// Inverse Mixing Columns
void invMixColumns(unsigned char Cipher_Text[4][4])
{
    unsigned char Output_Matrix[4][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Output_Matrix[i][j] = 0x00;
    int Multiplication_Matrix[4][4] = {{0x0e, 0x0b, 0x0d, 0x09},
                                       {0x09, 0x0e, 0x0b, 0x0d},
                                       {0x0d, 0x09, 0x0e, 0x0b},
                                       {0x0b, 0x0d, 0x09, 0x0e}};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Output_Matrix[j][i] = (galois_multiplication(Multiplication_Matrix[i][0], Cipher_Text[j][0]) ^
                                   galois_multiplication(Multiplication_Matrix[i][1], Cipher_Text[j][1])) ^
                                  (galois_multiplication(Multiplication_Matrix[i][2], Cipher_Text[j][2]) ^
                                   galois_multiplication(Multiplication_Matrix[i][3], Cipher_Text[j][3]));
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Cipher_Text[i][j] = Output_Matrix[i][j];
}

// Main Function
int main()
{
    cout << "Advanced Encryption Security(AES-128)" << endl;

    // Variables
    int Plain_Text[4][4];
    int Keys[4][4] = {0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00};
    int wordsFromKey[4][4], wordsFromPlain_Text[4][4];
    // Plain_Text: Double dimension Array for square of non enrypted text
    // Key: Used for Round Key Expansion
    // wordsFromKey: combined 4 bytes to a word in this array
    unsigned char Cipher_Text[4][4] = {{0x00, 0x00, 0x01, 0x01},
                                       {0x03, 0x03, 0x07, 0x07},
                                       {0x0f, 0x0f, 0x1f, 0x1f},
                                       {0x3f, 0x3f, 0x7f, 0x7f}};
    // A Sample Data Only
    cout << endl
         << "Data:" << endl;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            printf("%X ", Cipher_Text[i][j]);
        cout << endl;
    }
    cout << endl
         << "Encrypting Data...." << endl;
    //--------------------------Encrypting--------------------------------------
    // bitwise XOR with Keys(words)
    addRoundKey(Cipher_Text, Keys);
    // Adding Round Key
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            RoundKeys[0][i][j] = Keys[i][j];

KhushiTapariya, [11-07-2024 10:40]
// 10 Rounds for AES-128
    for (int i = 1; i <= 10; i++)
    {
        // Key Scheduler
        if (i == 1 || i == 2)
            Key_Expansion(Keys, i);
        else if (i == 3)
            Key_Expansion(Keys, 0x04);
        else if (i == 4)
            Key_Expansion(Keys, 0x08);
        else if (i == 5)
            Key_Expansion(Keys, 0x10);
        else if (i == 6)
            Key_Expansion(Keys, 0x20);
        else if (i == 7)
            Key_Expansion(Keys, 0x40);
        else if (i == 8)
            Key_Expansion(Keys, 0x80);
        else if (i == 9)
            Key_Expansion(Keys, 0x1b);
        else if (i == 10)
            Key_Expansion(Keys, 0x36);

        // Storing Round Keys
        for (int j = 0; j < 4; j++)
            for (int k = 0; k < 4; k++)
                RoundKeys[i][j][k] = Keys[j][k];

        // Transformations
        substituteBytes(Cipher_Text);
        shiftRows(Cipher_Text);
        if (i < 10) // Not in last one
            mixColumns(Cipher_Text);
        addRoundKey(Cipher_Text, Keys);
    }
    cout << endl
         << "Encrypted Text:" << endl;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            printf("%X ", Cipher_Text[i][j]);
        cout << endl;
    }
    cout << endl
         << endl
         << "Decrypting..." << endl;

    //-----------------------------Decrypting-------------------------------
    int Decrypting_Key[4][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Decrypting_Key[i][j] = Keys[i][j];
    // Initial Transformation
    addRoundKey(Cipher_Text, Decrypting_Key);
    // 10 Rounds for AES-128
    for (int i = 10; i >= 1; i--)
    {
        InvShiftRows(Cipher_Text);
        invSubstituteBytes(Cipher_Text);
        for (int k = 0; k < 4; k++)
            for (int l = 0; l < 4; l++)
                Decrypting_Key[k][l] = RoundKeys[i - 1][k][l];
        addRoundKey(Cipher_Text, Decrypting_Key);
        if (i != 1)
            invMixColumns(Cipher_Text);
    }
    cout << endl
         << "Decrypted Data:" << endl;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            printf("%X ", Cipher_Text[i][j]);
        cout << endl;
    }
    return 0;
}
