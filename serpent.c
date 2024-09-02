#include<stdio.h>
#include<stdint.h>

#define Nb 4
#define Nr 32
#define FRAC 0x9e3779b9
#define NUM_OF_NIST_KEYS 16

typedef struct key_sched_struct {
	unsigned int words[Nb * (Nr + 1)];
} *KeySched;

static const uint8_t sbox[8][16] = {
	{0x03, 0x08, 0x0f, 0x01, 0x0a, 0x06, 0x05, 0x0b, 0x0e, 0x0d, 0x04, 0x02, 0x07, 0x00, 0x09, 0x0c},
	{0x0f, 0x0c, 0x02, 0x07, 0x09, 0x00, 0x05, 0x0a, 0x01, 0x0b, 0x0e, 0x08, 0x06, 0x0d, 0x03, 0x04},
	{0x08, 0x06, 0x07, 0x09, 0x03, 0x0c, 0x0a, 0x0f, 0x0d, 0x01, 0x0e, 0x04, 0x00, 0x0b, 0x05, 0x02},
	{0x00, 0x0f, 0x0b, 0x08, 0x0c, 0x09, 0x06, 0x03, 0x0d, 0x01, 0x02, 0x04, 0x0a, 0x07, 0x05, 0x0e},
	{0x01, 0x0f, 0x08, 0x03, 0x0c, 0x00, 0x0b, 0x06, 0x02, 0x05, 0x04, 0x0a, 0x09, 0x0e, 0x07, 0x0d},
	{0x0f, 0x05, 0x02, 0x0b, 0x04, 0x0a, 0x09, 0x0c, 0x00, 0x03, 0x0e, 0x08, 0x0d, 0x06, 0x07, 0x01},
	{0x07, 0x02, 0x0c, 0x05, 0x08, 0x04, 0x06, 0x0b, 0x0e, 0x09, 0x01, 0x0f, 0x0d, 0x03, 0x0a, 0x00},
	{0x01, 0x0d, 0x0f, 0x00, 0x0e, 0x08, 0x02, 0x0b, 0x07, 0x04, 0x0c, 0x0a, 0x09, 0x03, 0x05, 0x06},
};

static const uint8_t inv_sbox[8][16] = {
	{0x0d, 0x03, 0x0b, 0x00, 0x0a, 0x06, 0x05, 0x0c, 0x01, 0x0e, 0x04, 0x07, 0x0f, 0x09, 0x08, 0x02},
	{0x05, 0x08, 0x02, 0x0e, 0x0f, 0x06, 0x0c, 0x03, 0x0b, 0x04, 0x07, 0x09, 0x01, 0x0d, 0x0a, 0x00},
	{0x0c, 0x09, 0x0f, 0x04, 0x0b, 0x0e, 0x01, 0x02, 0x00, 0x03, 0x06, 0x0d, 0x05, 0x08, 0x0a, 0x07},
	{0x00, 0x09, 0x0a, 0x07, 0x0b, 0x0e, 0x06, 0x0d, 0x03, 0x05, 0x0c, 0x02, 0x04, 0x08, 0x0f, 0x01},
	{0x05, 0x00, 0x08, 0x03, 0x0a, 0x09, 0x07, 0x0e, 0x02, 0x0c, 0x0b, 0x06, 0x04, 0x0f, 0x0d, 0x01},
	{0x08, 0x0f, 0x02, 0x09, 0x04, 0x01, 0x0d, 0x0e, 0x0b, 0x06, 0x05, 0x03, 0x07, 0x0c, 0x0a, 0x00},
	{0x0f, 0x0a, 0x01, 0x0d, 0x05, 0x03, 0x06, 0x00, 0x04, 0x09, 0x0e, 0x07, 0x02, 0x0c, 0x08, 0x0b},
	{0x03, 0x00, 0x06, 0x0d, 0x09, 0x0e, 0x0f, 0x08, 0x05, 0x0c, 0x0b, 0x07, 0x0a, 0x01, 0x04, 0x02}
};

unsigned int rotword(unsigned int a, unsigned int n) {
	return (((a) << n) | ((a) >> (32 - n)));
}

unsigned int inv_rotword(unsigned int a, unsigned int n) {
	return (((a) >> n) | ((a) << (32 - n)));
}

uint8_t sub_4bit(unsigned int which_sbox, unsigned int n) {
	return sbox[which_sbox][n];
}

uint8_t inv_sub_4bit(unsigned int which_sbox, unsigned int n) {
	return inv_sbox[which_sbox][n];
}

int serpent_set_encrypt_key(KeySched s, const uint8_t *k, unsigned int key_size) {
	unsigned int i, j, sub_temp, Nk = key_size >> 5;
	unsigned int temp[4];
	int which_sbox = 4;

	if (s == (KeySched)0) { return 1; }
	else if (k == (const uint8_t *)0) { return 1; }
	else if (Nk != 4 && Nk != 6 && Nk != 8) { return 1; }

	for (i = 0; i < Nb * (Nr+1); ++i) {
		if (i < Nk) {
			s->words[i] = (k[Nb * i] << 24) | (k[Nb * i + 1] << 16) |
						  (k[Nb * i + 2] << 8) | (k[Nb * i + 3]);
		}
		else if (i < 8) {
			s->words[i] = 0x00000000;
		}
		else {
			s->words[i] = rotword(s->words[i - 8] ^ s->words[i - 5] ^ s->words[i - 3] ^ s->words[i - 1] ^ FRAC ^ i, 11);
		}

		if ((i & 3) == 3) {
			which_sbox--;
			if (which_sbox < 0)
				which_sbox += 8;

			temp[0] = s->words[i - 3];
			temp[1] = s->words[i - 2];
			temp[2] = s->words[i - 1];
			temp[3] = s->words[i];

			s->words[i - 3] = 0x0000;
			s->words[i - 2] = 0x0000;
			s->words[i - 1] = 0x0000;
			s->words[i] = 0x0000;

			for (j = 0; j < 32; j++) {
				sub_temp = sub_4bit(which_sbox, (temp[3] & 0x01) << 3 | (temp[2] & 0x01) << 2 |
													(temp[1] & 0x01) << 1 | (temp[0] & 0x01));

				int f;
				for (f = 3; f >= 0; --f) {
					s->words[i - f] |= (sub_temp & 0x01) << j;
					sub_temp >>= 1;
				}
				temp[0] >>= 1;
				temp[1] >>= 1;
				temp[2] >>= 1;
				temp[3] >>= 1;
			}
		}
	}

	return 0;
}

int serpent_set_decrypt_key(KeySched s, const uint8_t *k, unsigned int key_size) {
	return serpent_set_encrypt_key(s, k, key_size);
}

void initial_permutation(uint8_t *s) {
	short i;

	for (i = 0; i < 128; ++i) {
		uint8_t b_position = ((i << 5) % 127);
		uint8_t bit_a = (1 << (i & 7)) & s[i >> 3];
		uint8_t bit_b = (1 << (b_position & 7)) & s[b_position >> 3];
		if (bit_a > 0 && bit_b == 0) {
			s[i >> 3] -= bit_a;
			s[b_position >> 3] += (1 << (b_position & 7));
		}
		else if (bit_a == 0 && bit_b > 0) {
			s[i >> 3] += (1 << (i & 7));
			s[b_position >> 3] -= bit_b;
		}
	}
}

void inv_initial_permutation(uint8_t *s) {
	short i;
	for (i = 127; i >= 0; --i) {
		uint8_t b_position = ((i << 5) % 127);
		uint8_t bit_a = (1 << (i & 7)) & s[i >> 3];
		uint8_t bit_b = (1 << (b_position & 7)) & s[b_position >> 3];
		if (bit_a > 0 && bit_b == 0) {
			s[i >> 3] -= bit_a;
			s[b_position >> 3] += (1 << (b_position & 7));
		}
		else if (bit_a == 0 && bit_b > 0) {
			s[i >> 3] += (1 << (i & 7));
			s[b_position >> 3] -= bit_b;
		}
	}
}

void add_round_key(uint8_t *s, const unsigned int *k) {
	s[0] ^= (uint8_t)(k[0] >> 24);
	s[1] ^= (uint8_t)(k[0] >> 16);
	s[2] ^= (uint8_t)(k[0] >> 8);
	s[3] ^= (uint8_t)(k[0]);

	s[4] ^= (uint8_t)(k[1] >> 24);
	s[5] ^= (uint8_t)(k[1] >> 16);
	s[6] ^= (uint8_t)(k[1] >> 8);
	s[7] ^= (uint8_t)(k[1]);

	s[8] ^= (uint8_t)(k[2] >> 24);
	s[9] ^= (uint8_t)(k[2] >> 16);
	s[10] ^= (uint8_t)(k[2] >> 8);
	s[11] ^= (uint8_t)(k[2]);

	s[12] ^= (uint8_t)(k[3] >> 24);
	s[13] ^= (uint8_t)(k[3] >> 16);
	s[14] ^= (uint8_t)(k[3] >> 8);
	s[15] ^= (uint8_t)(k[3]);
}

void sub_bytes(uint8_t *s, unsigned int round) {
	unsigned int i, j, sub_temp;
	unsigned int temp[4];
	for (i = 0; i < Nb; i++) {
		temp[i] = (s[Nb * i] << 24) | (s[Nb * i + 1] << 16) | (s[Nb * i + 2] << 8) | (s[Nb * i + 3]);
		s[Nb * i] = 0x00;
		s[Nb * i + 1] = 0x00;
		s[Nb * i + 2] = 0x00;
		s[Nb * i + 3] = 0x00;
	}

	for (j = 0; j < 32; j++) {
		sub_temp = sub_4bit(round % 8, (temp[3] & 0x80000000) >> 28 |
										   (temp[2] & 0x80000000) >> 29 | (temp[1] & 0x80000000) >> 30 | (temp[0] & 0x80000000) >> 31);
		// printf("before sub %x %x %x %x\n", (temp[3]&0x80000000) >> 28 , (temp[2]&0x80000000) >> 29 , (temp[1]&0x80000000) >> 30 , (temp[0]&0x80000000) >> 31);
		// printf("sub_temp %x\n", sub_temp);
		int f;
		for (f = 0; f < 4; ++f) {
			s[(j >> 3) + (f << 2)] |= (sub_temp & 0x01) << (7 - (j & 7));
			sub_temp >>= 1;
		}
		temp[0] <<= 1;
		temp[1] <<= 1;
		temp[2] <<= 1;
		temp[3] <<= 1;
	}
}

void inv_sub_bytes(uint8_t *s, unsigned int round) {
	unsigned int i, j, sub_temp;
	unsigned int temp[4];
	for (i = 0; i < Nb; i++) {
		temp[i] = (s[Nb * i] << 24) | (s[Nb * i + 1] << 16) | (s[Nb * i + 2] << 8) | (s[Nb * i + 3]);
		s[Nb * i] = 0x00;
		s[Nb * i + 1] = 0x00;
		s[Nb * i + 2] = 0x00;
		s[Nb * i + 3] = 0x00;
	}

	for (j = 0; j < 32; j++) {
		sub_temp = inv_sub_4bit(round % 8, (temp[3] & 0x80000000) >> 28 |
											   (temp[2] & 0x80000000) >> 29 | (temp[1] & 0x80000000) >> 30 | (temp[0] & 0x80000000) >> 31);

		// printf("before sub %x %x %x %x\n", (temp[3]&0x80000000) >> 28 , (temp[2]&0x80000000) >> 29 , (temp[1]&0x80000000) >> 30 , (temp[0]&0x80000000) >> 31);
		// printf("sub_temp %x\n", sub_temp);

		int f;
		for (f = 0; f < 4; ++f) {
			s[(j >> 3) + (f << 2)] |= (sub_temp & 0x01) << (7 - (j & 7));
			sub_temp >>= 1;
		}
		temp[0] <<= 1;
		temp[1] <<= 1;
		temp[2] <<= 1;
		temp[3] <<= 1;
	}
}

void linear_transformation(uint8_t *s) {
	unsigned int X[4], i;

	for (i = 0; i < Nb; ++i) {
		X[i] = (s[Nb * i] << 24) | (s[Nb * i + 1] << 16) | (s[Nb * i + 2] << 8) | (s[Nb * i + 3]);
	}

	X[0] = rotword(X[0], 13);
	X[2] = rotword(X[2], 3);
	X[1] ^= X[0] ^ X[2];
	X[3] ^= X[2] ^ (X[0] << 3);
	X[1] = rotword(X[1], 1);
	X[3] = rotword(X[3], 7);
	X[0] ^= X[1] ^ X[3];
	X[2] ^= X[3] ^ (X[1] << 7);
	X[0] = rotword(X[0], 5);
	X[2] = rotword(X[2], 22);

	for (i = 0; i < Nb; ++i) {
		s[Nb * i + 3] = (uint8_t)(X[i] & 0xff);
		s[Nb * i + 2] = (uint8_t)(X[i] >> 8 & 0xff);
		s[Nb * i + 1] = (uint8_t)(X[i] >> 16 & 0xff);
		s[Nb * i] = (uint8_t)(X[i] >> 24 & 0xff);
	}
}

void inv_linear_transformation(uint8_t *s) {
	unsigned int X[4], i;
	for (i = 0; i < Nb; ++i) {
		X[i] = (s[Nb * i] << 24) | (s[Nb * i + 1] << 16) | (s[Nb * i + 2] << 8) | (s[Nb * i + 3]);
	}
	
	X[2] = inv_rotword(X[2], 22);
	X[0] = inv_rotword(X[0], 5);
	X[2] ^= X[3] ^ (X[1] << 7);
	X[0] ^= X[1] ^ X[3];
	X[3] = inv_rotword(X[3], 7);
	X[1] = inv_rotword(X[1], 1);
	X[3] ^= X[2] ^ (X[0] << 3);
	X[1] ^= X[0] ^ X[2];
	X[2] = inv_rotword(X[2], 3);
	X[0] = inv_rotword(X[0], 13);
	
	for (i = 0; i < Nb; ++i) {
		s[Nb * i + 3] = (uint8_t)(X[i] & 0xff);
		s[Nb * i + 2] = (uint8_t)(X[i] >> 8 & 0xff);
		s[Nb * i + 1] = (uint8_t)(X[i] >> 16 & 0xff);
		s[Nb * i] = (uint8_t)(X[i] >> 24 & 0xff);
	}
}

void final_permutation(uint8_t *s) {
	short i;

	for (i = 0; i < 128; ++i) {
		uint8_t b_position = ((i << 1) % 127);
		uint8_t bit_a = (1 << (i & 7)) & s[i >> 3];
		uint8_t bit_b = (1 << (b_position & 7)) & s[b_position >> 3];
		if (bit_a > 0 && bit_b == 0) {
			s[i >> 3] -= bit_a;
			s[b_position >> 3] += (1 << (b_position & 7));
		}
		else if (bit_a == 0 && bit_b > 0) {
			s[i >> 3] += (1 << (i & 7));
			s[b_position >> 3] -= bit_b;
		}
	}
}

void inv_final_permutation(uint8_t *s) {
	short i;
	for (i = 127; i >= 0; --i) {
		uint8_t b_position = ((i << 1) % 127);
		uint8_t bit_a = (1 << (i & 7)) & s[i >> 3];
		uint8_t bit_b = (1 << (b_position & 7)) & s[b_position >> 3];

		if (bit_a > 0 && bit_b == 0) {
			s[i >> 3] -= bit_a;
			s[b_position >> 3] += (1 << (b_position & 7));
		}
		else if (bit_a == 0 && bit_b > 0) {
			s[i >> 3] += (1 << (i & 7));
			s[b_position >> 3] -= bit_b;
		}
	}
}

int serpent_encrypt(uint8_t *out, uint8_t *in, const KeySched s) {
	uint8_t state[Nb * Nb];
	unsigned int i;
	
	initial_permutation(in);
	for (i = 0;; ++i) {
		add_round_key(in, s->words + Nb * i);
		sub_bytes(in, i);
		if (i == Nr - 1)
			break;
		linear_transformation(in);
	}
	add_round_key(in, s->words + Nb * (Nr));
	final_permutation(in);
	
	for(i=0;i<16;i++)
		out[i] = in[i];
	
	return 0;
}

int serpent_decrypt(uint8_t *out, uint8_t *in, const KeySched s) {
	uint8_t state[Nb * Nb];
	unsigned int i;

	inv_final_permutation(in);
	add_round_key(in, s->words + Nb * (Nr));
	for (i = Nr - 1;; --i) {
		inv_sub_bytes(in, i);
		add_round_key(in, s->words + Nb * i);
		if (i == 0)
			break;
		inv_linear_transformation(in);
	}
	inv_initial_permutation(in);
	
	for(i=0;i<16;i++)
		out[i] = in[i];

	return 0;
}

uint8_t key_128[16] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

uint8_t key_192[24] = {
    0x1a, 0xbc, 0x34, 0x55, 0x67, 0x89, 0xab, 0xcd,
    0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
    0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde
};

uint8_t key_256[32] = {
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
    0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

uint8_t input[16] = {
	0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
	0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
};

int avalanche_effect_test(void)
{
	int result = 0, i, j, k, m, total_change = 0;
	double total_prob = 0.0;
	
	struct key_sched_struct s;
	uint8_t ciphertext[2][NUM_OF_NIST_KEYS];
	uint8_t decrypted[NUM_OF_NIST_KEYS];
	
	printf("\ninput:\t\t");
	for (i = 0; i < NUM_OF_NIST_KEYS; i++)
		printf("%2x ", input[i]);
	printf("\n");
	
	serpent_set_encrypt_key(&s, key_128, 128);
	if (serpent_encrypt(ciphertext[0], input, &s))
		printf("Encryption Error.");
		
	printf("\nciphertext :\t");
	for (i = 0; i < NUM_OF_NIST_KEYS; i++)
		printf("%2x ", ciphertext[0][i]);
	printf("\n");
		
		
	for(k = 0; k < NUM_OF_NIST_KEYS; k++) {
		uint8_t temp = input[k], bit_pointer = 0x80;
		for(i = 0; i < 8; i++) {
			if((input[k] & bit_pointer) == bit_pointer)
				input[k] &= 0x00;		
			else
				input[k] |= bit_pointer;
			
			serpent_encrypt(ciphertext[1], input, &s);
			input[k] = temp;
			bit_pointer >>= 1;
			
			printf("\nciphertext %d :\t", k*8+i+1);
			for (j = 0; j < NUM_OF_NIST_KEYS; j++)
				printf("%2x ", ciphertext[1][j]);
			printf("\n");
			
			uint8_t xor_num = 0;
			int prob_sum = 0;
			for(j = 0; j < NUM_OF_NIST_KEYS; j++) {
				xor_num = ciphertext[0][j] ^ ciphertext[1][j];
				while(xor_num > 0){
					if((xor_num & 0x01) == 0x01)
						prob_sum++;
					xor_num >>= 1;
				}
			}
			
			printf("change bit num:%d\n", prob_sum);
			printf("change prob:%f\n", prob_sum/128.0);
			total_change += prob_sum;
			total_prob += prob_sum/128.0;
		}
	}
	
	printf("\n");
	printf("change prob for 128 times test using total_change:\t%f\n", total_change/(128.0*128.0));
	printf("change prob for 128 times test using total_prob:\t%f\n", total_prob/128.0);

	return result;
}

int main() {
	struct key_sched_struct s;
	uint8_t ciphertext[16];
	uint8_t decrypted[16];
	int i;
	
	printf("\ninput :\t\t");
	for (i = 0; i < 16; i++)
		printf("%2x ", input[i]);
	
	serpent_set_encrypt_key(&s, key_256, 256);
	if (serpent_encrypt(ciphertext, input, &s))
		printf("Encryption Error.");
		
	printf("\nciphertext :\t");
	for (i = 0; i < 16; i++)
		printf("%2x ", ciphertext[i]);
		
	serpent_set_decrypt_key(&s, key_256, 256);
	if (serpent_decrypt(decrypted, ciphertext, &s))
		printf("Encryption Error.");
		
	printf("\ndecrypted :\t");
	for (i = 0; i < 16; i++)
		printf("%2x ", decrypted[i]);
	
	printf("\n\n\n");
	if(avalanche_effect_test())
		printf("Avalanche Effect Test Error.");
		
	return 0;
}

