all:
	gcc -std=c99 -o firm_builder firm_builder.c polarssl/sha2.c
