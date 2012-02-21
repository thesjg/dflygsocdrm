/*
 *	"enigma.c" is in file cbw.tar from
 *	anonymous FTP host watmsg.waterloo.edu: pub/crypt/cbw.tar.Z
 *
 *	A one-rotor machine designed along the lines of Enigma
 *	but considerably trivialized.
 *
 *	A public-domain replacement for the UNIX "crypt" command.
 *
 *	Upgraded to function properly on 64-bit machines.
 *
 * $FreeBSD: src/usr.bin/enigma/enigma.c,v 1.2.6.3 2001/08/01 23:51:34 obrien Exp $
 * $DragonFly: src/usr.bin/enigma/enigma.c,v 1.6 2005/01/05 18:42:33 liamfoy Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MINUSKVAR "CrYpTkEy"

#define ECHO 010
#define ROTORSZ 256
#define MASK 0377
char	t1[ROTORSZ];
char	t2[ROTORSZ];
char	t3[ROTORSZ];
char	deck[ROTORSZ];
char	buf[13];

static void	shuffle(char *);
static void	setup(const char *);

static void
setup(const char *pw)
{
	int ic, i, k, temp;
	char salt[3];
	unsigned rnd;
	long seed;
	char *cryptpw;

	strncpy(salt, pw, sizeof(salt));
	cryptpw = crypt(pw, salt);
	if (cryptpw == NULL) {
		fprintf(stderr, "crypt(3) failure\n");
		exit(1);
	}
	memcpy(buf, cryptpw, sizeof(buf));
	seed = 123;
	for (i=0; i<13; i++)
		seed = seed*buf[i] + i;
	for(i=0;i<ROTORSZ;i++) {
		t1[i] = i;
		deck[i] = i;
	}
	for(i=0;i<ROTORSZ;i++) {
		seed = 5*seed + buf[i%13];
		if( sizeof(long) > 4 )  {
			/* Force seed to stay in 32-bit signed math */
			if( seed & 0x80000000 )
				seed = seed | (-1L & ~0xFFFFFFFFL);
			else
				seed &= 0x7FFFFFFF;
		}
		rnd = seed % 65521;
		k = ROTORSZ-1 - i;
		ic = (rnd&MASK)%(k+1);
		rnd >>= 8;
		temp = t1[k];
		t1[k] = t1[ic];
		t1[ic] = temp;
		if(t3[k]!=0) continue;
		ic = (rnd&MASK) % k;
		while(t3[ic]!=0) ic = (ic+1) % k;
		t3[k] = ic;
		t3[ic] = k;
	}
	for(i=0;i<ROTORSZ;i++)
		t2[t1[i]&MASK] = i;
}

int
main(int argc, char **argv)
{
	int i, n1, n2, nr1, nr2;
	int secureflg = 0, kflag = 0;
	char *cp;

	if (argc > 1 && argv[1][0] == '-') {
		if (argv[1][1] == 's') {
			argc--;
			argv++;
			secureflg = 1;
		} else if (argv[1][1] == 'k') {
			argc--;
			argv++;
			kflag = 1;
		}
	}
	if (kflag) {
		if ((cp = getenv(MINUSKVAR)) == NULL) {
			fprintf(stderr, "%s not set\n", MINUSKVAR);
			exit(1);
		}
		setup(cp);
	} else if (argc != 2) {
		setup(getpass("Enter key:"));
	}
	else
		setup(argv[1]);
	n1 = 0;
	n2 = 0;
	nr2 = 0;

	while((i=getchar()) != -1) {
		if (secureflg) {
			nr1 = deck[n1]&MASK;
			nr2 = deck[nr1]&MASK;
		} else {
			nr1 = n1;
		}
		i = t2[(t3[(t1[(i+nr1)&MASK]+nr2)&MASK]-nr2)&MASK]-nr1;
		putchar(i);
		n1++;
		if(n1==ROTORSZ) {
			n1 = 0;
			n2++;
			if(n2==ROTORSZ) n2 = 0;
			if (secureflg) {
				shuffle(deck);
			} else {
				nr2 = n2;
			}
		}
	}

	return 0;
}

static void
shuffle(char *deckary)
{
	int i, ic, k, temp;
	unsigned rnd;
	static long seed = 123;

	for(i=0;i<ROTORSZ;i++) {
		seed = 5*seed + buf[i%13];
		rnd = seed % 65521;
		k = ROTORSZ-1 - i;
		ic = (rnd&MASK)%(k+1);
		temp = deckary[k];
		deckary[k] = deckary[ic];
		deckary[ic] = temp;
	}
}
