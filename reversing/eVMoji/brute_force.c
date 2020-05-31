#include <stdlib.h>
#include <stdio.h>
char alpha[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";

int is_correct(int in) {
		unsigned int acc = 0xffffffff; // value at [140] is 0xffffffff
		for (int i = 0; i < 32; i++) {
			if ((acc & 1) != ((in >> i) & 1)) {
				acc >>= 1;
				acc ^= 0xedb88320;  // the value at [128] is 0xedb88320
			} else {
				acc >>= 1;
			}
		}
		return (acc ^ 0xf40e845e) == 0; // value at [136] is 0xf40e845e
}


int main(int argc, char* argv[]) {
		char input[5];
		input[4] = '\0';
		for (unsigned int num = 0; num < 81450625; num ++) {
			int f = num;
			for (int i = 0; i <4; i++) {
					input[i] = alpha[f % 95];
					f /= 95;
			}
			if (num % 1000000 == 0) {
				printf("At : %d/81450625 %s\n", num, input);
			}
			int* ptr = (int*)input;
			if (is_correct(*ptr)) {
				printf("GOT %s\n", input);
			}
		}
}
