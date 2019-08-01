#ifndef ECC__H
#define ECC__H
#define ECC_512_SIZE 3
void calculate_ecc(const unsigned char *buf, unsigned int eccsize,
		       unsigned char *code);
int correct_data(unsigned char *buf,
			unsigned char *read_ecc, unsigned char *calc_ecc,
			unsigned int eccsize);
#endif
