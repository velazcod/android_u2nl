all: u2nl

u2nl: u2nl.c
	gcc -Wall -g u2nl.c -o u2nl
	
