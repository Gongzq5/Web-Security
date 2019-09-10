#include "MD5.hpp"
using namespace std;

int main(int argc, char* argv[]) {
    char* fileName = new char[1024];
    if (argc < 2) {
        printf("Please input source file name.\n");
        exit(1);
    }
    MD5 md5;
    md5.encrypt(argv[1]);
    return 0;
}
