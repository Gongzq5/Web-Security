# README

**！！写了一个示例在`des.cpp`中！！**

## 编译

使用g++编译，需要使用`-std=c++11`

```powershell
$ g++ des.cpp -o des.exe -std=c++11
```

## 用法
1. 使用指定的64位秘钥生成DES实例

  秘钥为`bitset<64>`类型

  ```cpp
  bitset<64> K = 0x1234567818;
  DES des(K);
  ```

  下面我们使用这个指定的`des`实例来进行DES加密解密

2. 加密解密文件

  ```cpp
  des.encryptFile();
  des.decryptFile();
  ```

  均有可选参数：
  * 加密的参数为：明文文件名，输出密文文件的文件名
  * 解密的参数为：密文文件名，输出解密信息的文件名

3. 加密解密64位块

  ```cpp
  bitset<64> plaintext  = 0x5555555555555555;
  bitset<64> cipher     = des.encrypt64(plaintext);
  bitset<64> decryption = des.decrypt64(cipher);
  ```

## 程序结构接口

```cpp
class DES {
public:

  DES(bitset<64> Key);

  void encryptFile(const char* plaintextFileName = "plaintext.txt",
                    const char* cipherFileName = "cipher.txt") ;

  void decryptFile(const char* cipherFileName = "cipher.txt",
                    const char* decryptionFileName = "decryptionResult.txt") ;

  bitset<64> encrypt64(bitset<64> plaintext) ;

  bitset<64> decrypt64(bitset<64> cipher) ;

private:
  ...
};

```

## 其他

* 加密文件时会将文件末尾不足8字节的部分补全，将不足8字节的部分都填充为空字节的个数。考虑到无法确定是否是自己添加的字节，因此无法有效地去除这部分字节。所以解密时可能会多出来几位。
