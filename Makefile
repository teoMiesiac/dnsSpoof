dnspoof.o:
	gcc dnsspoof.c -o dnsspoof -lnet -lpcap -lpthread
