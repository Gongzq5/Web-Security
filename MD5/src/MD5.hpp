#ifndef _MD5_HPP_
#define _MD5_HPP_

#include <memory.h>
#include <stdio.h>
#include <fstream>
#include <functional>

using std::ios;
typedef unsigned uint;

class MD5 {
public:
    static const int PADDING_MOD_BASE = 448;
    static const int CHUNK_SIZE = 512;
    static const int CV_SIZE = 128;
    uint A = 0x67452301, 
         B = 0xEFCDAB89,
         C = 0x98BADCFE,
         D = 0x10325476;
public:
    MD5() {}

    char* encrypt(const char* fileName) {
        A = 0x67452301, B = 0xEFCDAB89, C = 0x98BADCFE, D = 0x10325476;
        long long K = 0;
        char buffer[65]; memset(buffer, 0, 65);
        std::ifstream is(fileName, ios::binary|ios::in);
        if (!is) {
            // printf("\033[1m\033[45;33m No such file. \033[0m\n");
            printf("No such file.\n");
            exit(1);
        }
        // get file size
        long t1 = is.tellg();
        is.seekg(0, ios::end);
        long t2 = is.tellg();
        long fileSize = t2 - t1;
        is.seekg(0);
        while (K <= fileSize - 64) {
            K += 64;
            memset(buffer, 0, 65);
            is.read(buffer, 64);
            printf("%s\n", buffer);
            hmd5(buffer);
        }
        memset(buffer, 0, 65);
        if (K == fileSize) {
            padding(buffer, fileSize*8, fileSize-K);
            hmd5(buffer);
        } else {
            is.read(buffer, fileSize-K);
            padding(buffer, fileSize*8, fileSize-K);
            hmd5(buffer);
        }
        outputResult();
    }

    char* padding(char src[64], int K, int len)  {
        // printf("Before padding.\n");
        // for (int i=0; i<64; i++) {
        //     for (int j=7; j>=0; j--) printf("%d", (src[i]>>j)&1);
        //     if ((1+i)%8==0) printf("\n");
        //     else printf(" ");
        // }
        // Calculate how many bits are needed to be padding
        int P = PADDING_MOD_BASE - (K % CHUNK_SIZE);
        // When originSize == 448, we need to make P = 512;
        if (P == 0) P = CHUNK_SIZE;
        // Padding with 10000...00000
        // set to 0 first.
        memset(src+len*sizeof(char), 0, 64-len);
        // set the first byte to be padding is 10000000
        memset(src+len*sizeof(char), 0x80, 1);
        // set the last 64 bits (8 bytes) is K%64, src+64-8=src+56 
        memcpy(src+56*sizeof(char), &K, 8);
        // printf("After padding.\n");
        // for (int i=0; i<64; i++) {
        //     for (int j=7; j>=0; j--) printf("%d", (src[i]>>j)&1);
        //     if ((1+i)%8==0) printf("\n");
        //     else printf(" ");
        // }
        return src;
    }

    void hmd5(char src[64]) {
        uint a = A, b = B, c = C, d = D;        
        // split 512 bits data into 16 32 bits teams.
        uint team32[16];
        for (int i = 0; i < 16; i++) {            
            memcpy(&team32[i], src+i*4, 4);
        }
        // 4轮循环
        for (int i = 0; i < 4; i++) {
            // 16轮迭代
            std::function<uint(uint)> k_genarator;
            switch (i) {
                case 0: k_genarator = [] (uint _j) -> uint { return _j; }; break;
                case 1: k_genarator = [] (uint _j) -> uint { return (1 + 5*_j)%16; }; break;
                case 2: k_genarator = [] (uint _j) -> uint { return (5 + 3*_j)%16; }; break;
                case 3: k_genarator = [] (uint _j) -> uint { return (7*_j)%16; }; break;
            }
            for (int j = 0; j < 16; j++) {
                iterateOperation(i, team32[k_genarator(j)], T[i*16+j], s[i*16+j]);
                cycleShiftBuffer();
            }
        }
        A = A + a;
        B = B + b;
        C = C + c;
        D = D + d;
    }

    void outputResult() {
        printf("Output result.\n");
        char s[17]; memset(s, 0, 17);
        memcpy(s, &A, 4);memcpy(s+4, &B, 4);memcpy(s+8, &C, 4);memcpy(s+12, &D, 4);
        for (int i = 0; i < 16; i++) {
            printf("%02X", (s[i]&0xff));
        }
        printf("\n");
    }
/***********************  Some functions **************************/
    // a <- b + ((a + g(b, c, d) + X[k] + T[i]) <<<s)
    void iterateOperation(int which, uint X_k, uint T_i, uint s_i) {
        uint re = 0;
        switch (which) {
            case 0 : re = F(B, C, D); break;
            case 1 : re = G(B, C, D); break;
            case 2 : re = H(B, C, D); break;
            case 3 : re = I(B, C, D); break;
        }
        A = B + CLS(A + re + X_k + T_i, s_i);
    }

    // Tested
    void cycleShiftBuffer() {
        uint t = A;        
        A = D; // A <- D
        D = C; // D <- C
        C = B; // C <- B
        B = t; // B <- A
    }

/************************ Some functions **************************/
    static uint F(uint b, uint c, uint d) { return (b&c)|(~b&d); }
    static uint G(uint b, uint c, uint d) { return (b&d)|(c&~d); }
    static uint H(uint b, uint c, uint d) { return b^c^d; }
    static uint I(uint b, uint c, uint d) { return c^(b|~d); }

/************************** resources *****************************/
    uint T[64] = {0xd76aa478,  0xe8c7b756,  0x242070db,  0xc1bdceee,
                  0xf57c0faf,  0x4787c62a,  0xa8304613,  0xfd469501,  
                  0x698098d8,  0x8b44f7af,  0xffff5bb1,  0x895cd7be,  
                  0x6b901122,  0xfd987193,  0xa679438e,  0x49b40821,  
                  0xf61e2562,  0xc040b340,  0x265e5a51,  0xe9b6c7aa,  
                  0xd62f105d,  0x02441453,  0xd8a1e681,  0xe7d3fbc8,  
                  0x21e1cde6,  0xc33707d6,  0xf4d50d87,  0x455a14ed,  
                  0xa9e3e905,  0xfcefa3f8,  0x676f02d9,  0x8d2a4c8a, 
                  0xfffa3942,  0x8771f681,  0x6d9d6122,  0xfde5380c, 
                  0xa4beea44,  0x4bdecfa9,  0xf6bb4b60,  0xbebfbc70, 
                  0x289b7ec6,  0xeaa127fa,  0xd4ef3085,  0x04881d05, 
                  0xd9d4d039,  0xe6db99e5,  0x1fa27cf8,  0xc4ac5665, 
                  0xf4292244,  0x432aff97,  0xab9423a7,  0xfc93a039, 
                  0x655b59c3,  0x8f0ccc92,  0xffeff47d,  0x85845dd1, 
                  0x6fa87e4f,  0xfe2ce6e0,  0xa3014314,  0x4e0811a1, 
                  0xf7537e82,  0xbd3af235,  0x2ad7d2bb,  0xeb86d391 };

    uint s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

/*************************** Utils ********************************/
    static uint CLS(uint n, int s) {
        return (n >> (32 - s)) | (n << s);
    }
};

#endif
