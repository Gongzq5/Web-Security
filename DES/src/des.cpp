#include <bitset>
#include <iostream>
#include "DES.H"

using namespace std;

int main(void) {
	// 新建秘钥K
	bitset<64> K = 0x1234567818;

	// 使用该秘钥生成des实例
	DES des(K);

	// 加密文件
	// void encryptFile(const char* plaintextFileName = "plaintext.txt", 
    //                const char* cipherFileName = "cipher.txt")
	des.encryptFile("flower.bmp", "flowerCipher.bmp");
	// 解密文件
	// void decryptFile(const char* cipherFileName = "cipher.txt", 
    //                const char* decryptionFileName = "decryptionResult.txt")
	des.decryptFile("flowerCipher.bmp", "flowerDec.bmp");

	bitset<64> t = 0x5555555555555555;
	cout << "source     ---> " << t << endl;
	// 加密64位块
	bitset<64> c = des.encrypt64(t);
	cout << "cipher     ---> " << c << endl;
	// 解密64位块
	bitset<64> d = des.decrypt64(c);
	cout << "decrypt to ---> " << d << endl;

	cout << "// we can show the difference between the source and decryption" << endl;
	cout << "difference ---> " << (t^d) << endl;
	return 0;
}
