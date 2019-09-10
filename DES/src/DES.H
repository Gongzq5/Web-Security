/*!
 * @file       DES.H
 * @brief      提供了使用DES算法加密和解密的操作
 *             用法：
 *             1. 使用秘钥K新建DES类实例
 *             2. 方法提供在public的接口中
 *             
 * @author     gongzq5
 * @date       2018.10.21
 */  

#ifndef _DES_H_
#define _DES_H_

#include <bitset>
#include <iostream>
#include <fstream>

using namespace std;

/**
 * @brief      DES类 注意我们使用了bitset类，直接用cout输出bitset时
 *             其输出顺序是和下标访问顺序相反的，即cout时，输出为(假设为bitset<64>) 
 *              {bs[63], bs[62], ..., bs[0]} 
 *             为了方便，我们按照下标访问的顺序来看这个bitset 即我们将bitset视为 
 *              {bs[0], bs[1], bs[2], ..., bs[63]}
 */
class DES {

public:
    DES(bitset<64> K_) {
        K = K_;
        produceKi();
    }

    /**
     * @brief      加密一个文件 encrpt a file
     *
     * @param[in]  plaintextFileName  The plaintext file name
     * @param[in]  cipherFileName     The cipher file name for output
     */
    void encryptFile(const char* plaintextFileName = "plaintext.txt", 
                    const char* cipherFileName = "cipher.txt") {
        ifstream in;
        ofstream out;
        
        int count8 = 0;
        char char8[8];
        char oneChar;
        
        in.open(plaintextFileName, ios::binary);
        out.open(cipherFileName, ios::binary);
        while (in.get(oneChar)) {
            char8[count8++] = oneChar;
            if (count8 == 8) {
                bitset<64> tmp = ToBitset64(char8);
                bitset<64> cipher = encrypt64(tmp);
                out.write((char*)&cipher, sizeof(cipher));
                count8 = 0;
            }
        }
        if (count8 != 0) {
            bitset<64> tmp = ToBitset64(char8, count8);
            bitset<64> cipher = encrypt64(tmp);
            out.write((char*)&cipher, sizeof(cipher));
        }
        in.close();
        out.close();
    }

    /**
     * @brief      解密一个文件 decrpt a file
     *
     * @param[in]  cipherFileName      The cipher file name
     * @param[in]  decryptionFileName  The decryption file name for output
     */
    void decryptFile(const char* cipherFileName = "cipher.txt", 
                    const char* decryptionFileName = "decryptionResult.txt") {
        ifstream in;
        ofstream out;
        
        int count8 = 0;
        char char8[8];
        char oneChar;
        
        in.open(cipherFileName, ios::binary);
        out.open(decryptionFileName, ios::binary);
        while (in.get(oneChar)) {
            char8[count8++] = oneChar;
            if (count8 == 8) {
                bitset<64> tmp = ToBitset64(char8);
                bitset<64> cipher = decrypt64(tmp);
                out.write((char*)&cipher, sizeof(cipher));
                count8 = 0;
            }
        }
        if (count8 != 0) {
            bitset<64> tmp = ToBitset64(char8, count8);
            bitset<64> cipher = decrypt64(tmp);
            out.write((char*)&cipher, sizeof(cipher));
        }
        in.close();
        out.close();
    }

    /**
     * @brief      static function to produce a cipher from a plaintext
     *
     * @param      plaintext  The plaintext
     *
     * @return     the cipher text
     */
    bitset<64> encrypt64(bitset<64> plaintext) {
        bitset<64> cipher;
        cipher = IPPermutation(plaintext);
        cipher = iterationT(cipher);
        cipher = IP_1Permutation(cipher);
        return cipher;
    }

    /**
     * @brief      static function for decrypt the cipher text
     *
     * @param      cipher  The cipher
     *
     * @return     the plain text
     */
    bitset<64> decrypt64(bitset<64> cipher) {
        bitset<64> RL = IPPermutation(cipher);
        bitset<64> M0 = decryptionIterate(RL);
        bitset<64> M = IP_1Permutation(M0);
        return M;
    }

private:
    bitset<64> K;
    bitset<48> subK[16];
    
    void produceKi() {
        bitset<56> C_D = PC_1Permutation(K);
        bitset<28> C, D;

        for (int i = 0; i < 28; i++) C[i] = C_D[i];
        for (int i = 0; i < 28; i++) D[i] = C_D[i+28];

        for (int i = 0; i < 16; i++) {
            C = shiftLeft(C, shiftBits[i]);
            D = shiftLeft(D, shiftBits[i]);
            
            for (int i = 0; i < 28; i++) C_D[i] = C[i];
            for (int i = 0; i < 28; i++) C_D[i+28] = D[i];

            subK[i] = PC_2Permutation(C_D);
        }
    }
    
    // 加密过程中的16轮迭代
    bitset<64> iterationT(const bitset<64> text) {
        bitset<32> L0, R0;

        for (int i = 0; i < 32; i++) L0[i] = text[i];
        for (int i = 32; i < 64; i++) R0[i-32] = text[i];

        // showBitset(L0); showBitset(R0);
        // 16次迭代得到 {L16,R16}
        for (int i = 0; i < 16; i++) {
            bitset<32> L1 = R0;
            bitset<32> R1 = L0 ^ feistal(R0, subK[i]);
            L0 = L1; R0 = R1;
            // cout << "L" << i+1 << " : " ; showBitset(L0);
            // cout << "R" << i+1 << " : " ; showBitset(R0);
        }

        bitset<64> re;
        // re should be {R16,L16}
        for (int i = 0; i < 32; i++) re[i] = R0[i];
        for (int i = 32; i < 64; i++) re[i] = L0[i-32];

        // showBitset(re);
        return re;
    }

    // 解密过程中的16轮迭代
    bitset<64> decryptionIterate(const bitset<64> RL) {
        bitset<32> L, R;
        bitset<32> A, G, H, B;

        for (int i = 0; i < 32; i++) R[i] = RL[i];
        for (int i = 0; i < 32; i++) L[i] = RL[i+32];

        A = R, B = L;
        // 16次迭代得到 {L16,R16}
        for (int i = 0; i < 16; i++) {
            G = B;
            H = A ^ feistal(B, subK[16-i-1]);

            A = G;  B = H;
        }

        bitset<64> M0;
        // re should be {R16,L16}
        for (int i = 0; i < 32; i++) M0[i] = B[i];
        for (int i = 32; i < 64; i++) M0[i] = A[i-32];

        return M0;
    }

    bitset<32> feistal(bitset<32> S, bitset<48> Ki) {
        bitset<48> E = E_expand(S);
        E = E^Ki;
        bitset<32> re; 
        int reIndex = 0;
        bitset<6> t;
        for (int i = 0; i < 48; i++) {
            t[i%6] = E[i];
            if ((i+1)%6 == 0) {
                bitset<4> STresult = SBoxTransform(t, i/6);
                for (int i = 0; i < 4; i++) {
                    re[reIndex++] = STresult[i];
                }
            }
        }
        re = PPermutation(re);
        return re;
    }

    bitset<64> IPPermutation(const bitset<64> text) {
        bitset<64> re;
        for (int i = 0; i < 64; i++) {
            re[i] = text[IP[i]-1];
        }
        return re;
    }

    bitset<64> IP_1Permutation(const bitset<64> text) {
        bitset<64> re;
        for (int i = 0; i < 64; i++) {
            re[i] = text[IP_1[i]-1];
        }
        return re;
    }

    bitset<48> E_expand(bitset<32> S) {
        bitset<48> re;
        for (int i = 0; i < 48; i++) {
            re[i] = S[E[i]-1];
        }
        return re;
    }

    bitset<4> SBoxTransform(bitset<6> S, int indexOfBox) {
        int n = S[0]*2 + S[5];
        int m = 8*S[1] + 4*S[2] + 2*S[3] + S[4];
        bitset<4> re(S_BOX[indexOfBox][n][m]);
        return reverse(re);
    }

    bitset<32> PPermutation(bitset<32> S) {
        bitset<32> re;
        for (int i = 0; i < 32; i++) {
            re[i] = S[P[i]-1];
        }
        return re;
    } 

    bitset<56> PC_1Permutation(bitset<64> sK) {        
        bitset<56> re;
        for (int i = 0; i < 56; i++) 
            re[i] = sK[PC_1[i]-1];
        return re;
    }

    bitset<48> PC_2Permutation(bitset<56> C_D) {
        bitset<48> re;
        for (int i = 0; i < 48; i++) {
            re[i] = C_D[PC_2[i]-1];
        }
        return re;
    }

// 一些我们需要的辅助函数
    
    template <size_t T> 
    static void showBitset (bitset<T> s, bool nl = true) {
        for (int i = 0; i < T; i++) cout << s[i];
        if (nl) cout << endl;
    }

    template <size_t T> 
    static bitset<T> reverse (bitset<T> s) {
        bitset<T> re;
        for (int i = 0; i < T; i++) re[T-i-1] = s[i];
        return re;
    }

    bitset<64> ToBitset64(char s[8], int len = 8) {
        for (int i = len; i < 8; i++) s[i] = 8 - len;
        bitset<64> bits;
        for(int i=0; i<8; ++i)
            for(int j=0; j<8; ++j)
                bits[i*8+j] = ((s[i]>>j) & 1);
        return bits;
    }

    // 循环移位
    template <size_t T> 
    bitset<T> shiftLeft(bitset<T> K, int shiftLen) {
        bitset<T> re;
        for (int i = 0; i < T - shiftLen; i++) {
            re[i] = K[i+shiftLen];
        }
        for (int i = 0; i < shiftLen; i++) {
            re[i + T - shiftLen] = K[i];
        }
        return re;
    }

// 进行DES所需的资源

    const int IP[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
                        60, 52, 44, 36, 28, 20, 12, 4,
                        62, 54, 46, 38, 30, 22, 14, 6,
                        64, 56, 48, 40, 32, 24, 16, 8,
                        57, 49, 41, 33, 25, 17, 9,  1,
                        59, 51, 43, 35, 27, 19, 11, 3,
                        61, 53, 45, 37, 29, 21, 13, 5,
                        63, 55, 47, 39, 31, 23, 15, 7 };

    const int IP_1[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
                                39, 7, 47, 15, 55, 23, 63, 31,
                                38, 6, 46, 14, 54, 22, 62, 30,
                                37, 5, 45, 13, 53, 21, 61, 29,
                                36, 4, 44, 12, 52, 20, 60, 28,
                                35, 3, 43, 11, 51, 19, 59, 27,
                                34, 2, 42, 10, 50, 18, 58, 26,
                                33, 1, 41,  9, 49, 17, 57, 25};

    const int E[48] = {   32,  1,  2,  3,  4,  5,
                                4,  5,  6,  7,  8,  9,
                                8,  9, 10, 11, 12, 13,
                               12, 13, 14, 15, 16, 17,
                               16, 17, 18, 19, 20, 21,
                               20, 21, 22, 23, 24, 25,
                               24, 25, 26, 27, 28, 29,
                               28, 29, 30, 31, 32,  1};

    const int S_BOX[8][4][16] = { 
                                    {  
                                        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},  
                                        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},  
                                        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0}, 
                                        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} 
                                    },
                                    {  
                                        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},  
                                        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5}, 
                                        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},  
                                        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}  
                                    }, 
                                    {  
                                        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},  
                                        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},  
                                        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},  
                                        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}  
                                    }, 
                                    {  
                                        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},  
                                        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},  
                                        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},  
                                        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}  
                                    },
                                    {  
                                        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},  
                                        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},  
                                        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},  
                                        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}  
                                    },
                                    {  
                                        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},  
                                        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},  
                                        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},  
                                        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}  
                                    }, 
                                    {  
                                        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},  
                                        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},  
                                        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},  
                                        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}  
                                    }, 
                                    {  
                                        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},  
                                        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},  
                                        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},  
                                        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}  
                                    }};

    const int P[32] = {   16,  7, 20, 21,
                               29, 12, 28, 17,
                                1, 15, 23, 26,
                                5, 18, 31, 10,
                                2,  8, 24, 14,
                               32, 27,  3,  9,
                               19, 13, 30,  6,
                               22, 11,  4, 25};

    const int PC_1[56] = {  57, 49, 41, 33, 25, 17, 9,
                           1, 58, 50, 42, 34, 26, 18,
                          10,  2, 59, 51, 43, 35, 27,
                          19, 11,  3, 60, 52, 44, 36,
                          63, 55, 47, 39, 31, 23, 15,
                           7, 62, 54, 46, 38, 30, 22,
                          14,  6, 61, 53, 45, 37, 29,
                          21, 13,  5, 28, 20, 12,  4}; 
     
    const int PC_2[48] = {  14, 17, 11, 24,  1,  5,
                           3, 28, 15,  6, 21, 10,
                          23, 19, 12,  4, 26,  8,
                          16,  7, 27, 20, 13,  2,
                          41, 52, 31, 37, 47, 55,
                          30, 40, 51, 45, 33, 48,
                          44, 49, 39, 56, 34, 53,
                          46, 42, 50, 36, 29, 32};
     
    const int shiftBits[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
};

#endif