/*
 * Copyright (c) 1980, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#)mkfs.c	8.11 (Berkeley) 5/3/95
 * $FreeBSD: src/sbin/newfs/mkfs.c,v 1.29.2.6 2001/09/21 19:15:21 dillon Exp $
 * $DragonFly: src/sbin/newfs/mkfs.c,v 1.14 2007/05/20 19:29:21 dillon Exp $
 */

#include "defs.h"

#include <inttypes.h>
#include <stdlib.h>
#include <sys/ioctl_compat.h>

/*
 * make file system for cylinder-group style file systems
 */

/*
 * We limit the size of the inode map to be no more than a
 * third of the cylinder group space, since we must leave at
 * least an equal amount of space for the block map.
 *
 * N.B.: MAXIPG must be a multiple of INOPB(fs).
 */
#define MAXIPG(fs)	roundup((fs)->fs_bsize * NBBY / 3, INOPB(fs))

#define UMASK		0755
#define MAXINOPB	(MAXBSIZE / sizeof(struct ufs1_dinode))
#define POWEROF2(num)	(((num) & ((num) - 1)) == 0)

#ifdef STANDALONE
#error "mkfs.c: STANDALONE compilation no longer supported"
#endif

/*
 * variables set up by front end.
 */
extern int	mfs;		/* run as the memory based filesystem */
extern char	*mfs_mtpt;	/* mount point for mfs          */ 
extern struct stat mfs_mtstat;	/* stat prior to mount          */
extern int	Lflag;		/* add a volume label */
extern int	Nflag;		/* run mkfs without writing file system */
extern int	Oflag;		/* format as an 4.3BSD file system */
extern int	Uflag;		/* enable soft updates for file system */
extern int	Eflag;		/* erase contents using TRIM */
extern uint64_t	slice_offset;	/* Pysical device slice offset */
extern u_long	fssize;		/* file system size */
extern int	ntracks;	/* # tracks/cylinder */
extern int	nsectors;	/* # sectors/track */
extern int	nphyssectors;	/* # sectors/track including spares */
extern int	secpercyl;	/* sectors per cylinder */
extern int	sectorsize;	/* bytes/sector */
extern int	realsectorsize;	/* bytes/sector in hardware*/
extern int	rpm;		/* revolutions/minute of drive */
extern int	interleave;	/* hardware sector interleave */
extern int	trackskew;	/* sector 0 skew, per track */
extern int	fsize;		/* fragment size */
extern int	bsize;		/* block size */
extern int	cpg;		/* cylinders/cylinder group */
extern int	cpgflg;		/* cylinders/cylinder group flag was given */
extern int	minfree;	/* free space threshold */
extern int	opt;		/* optimization preference (space or time) */
extern int	density;	/* number of bytes per inode */
extern int	maxcontig;	/* max contiguous blocks to allocate */
extern int	rotdelay;	/* rotational delay between blocks */
extern int	maxbpg;		/* maximum blocks per file in a cyl group */
extern int	nrpos;		/* # of distinguished rotational positions */
extern int	bbsize;		/* boot block size */
extern int	sbsize;		/* superblock size */
extern int	avgfilesize;	/* expected average file size */
extern int	avgfilesperdir;	/* expected number of files per directory */
extern caddr_t	membase;	/* start address of memory based filesystem */
extern char *	filename;
extern u_char	*volumelabel;	/* volume label for filesystem */
extern struct disktab geom;

extern void fatal(const char *fmt, ...);

union {
	struct fs fs;
	char pad[SBSIZE];
} fsun;
#define	sblock	fsun.fs
struct	csum *fscs;

union {
	struct cg cg;
	char pad[MAXBSIZE];
} cgun;
#define	acg	cgun.cg

struct ufs1_dinode zino[MAXBSIZE / sizeof(struct ufs1_dinode)];

int	fsi, fso;
static fsnode_t copyroot;
static fsnode_t copyhlinks;
#ifdef FSIRAND
int     randinit;
#endif
daddr_t	alloc(int, int);
long	calcipg(long, long, off_t *);
static int charsperline(void);
void clrblock(struct fs *, unsigned char *, int);
void fsinit(time_t);
void initcg(int, time_t);
int isblock(struct fs *, unsigned char *, int);
void iput(struct ufs1_dinode *, ino_t);
int makedir(struct direct *, int);
void parentready(int);
void rdfs(daddr_t, int, char *);
void setblock(struct fs *, unsigned char *, int);
void started(int);
void erfs(off_t, off_t);
void wtfs(daddr_t, int, char *);
void wtfsflush(void);

int mfs_ppid = 0;
int parentready_signalled;

void
mkfs(char *fsys, int fi, int fo, const char *mfscopy)
{
	long i, mincpc, mincpg, inospercg;
	long cylno, rpos, blk, j, emitwarn = 0;
	long used, mincpgcnt, bpcg;
	off_t usedb;
	long mapcramped, inodecramped;
	long postblsize, rotblsize, totalsbsize;
	int status, fd;
	time_t utime;
	quad_t sizepb;
	int width;
	char tmpbuf[100];	/* XXX this will break in about 2,500 years */

	time(&utime);
#ifdef FSIRAND
	if (!randinit) {
		randinit = 1;
		srandomdev();
	}
#endif
	if (mfs) {
		int omask;
		pid_t child;

		mfs_ppid = getpid();
		signal(SIGUSR1, parentready);
		if ((child = fork()) != 0) {
			/*
			 * Parent
			 */
			if (child == -1)
				err(10, "mfs");
			if (mfscopy)
			    copyroot = FSCopy(&copyhlinks, mfscopy);
			signal(SIGUSR1, started);
			kill(child, SIGUSR1);
			while (waitpid(child, &status, 0) != child)
				;
			exit(WEXITSTATUS(status));
			/* NOTREACHED */
		}

		/*
		 * Child
		 */
		omask = sigblock(sigmask(SIGUSR1));
		while (parentready_signalled == 0)
			sigpause(omask);
		sigsetmask(omask);
		if (filename != NULL) {
			unsigned char buf[BUFSIZ];
			unsigned long l, l1;
			ssize_t w;

			fd = open(filename, O_RDWR|O_TRUNC|O_CREAT, 0644);
			if(fd < 0)
				err(12, "%s", filename);
			l1 = fssize * sectorsize;
			if (l1 > BUFSIZ)
				l1 = BUFSIZ;
			for (l = 0; l < fssize * (u_long)sectorsize; l += l1) {
				w = write(fd, buf, l1);
				if (w < 0 || (u_long)w != l1)
					err(12, "%s", filename);
			}
			membase = mmap(NULL, fssize * sectorsize,
				       PROT_READ|PROT_WRITE,
				       MAP_SHARED, fd, 0);
			if (membase == MAP_FAILED)
				err(12, "mmap");
			close(fd);
		} else {
			membase = mmap(NULL, fssize * sectorsize,
				       PROT_READ|PROT_WRITE,
				       MAP_SHARED|MAP_ANON, -1, 0);
			if (membase == MAP_FAILED)
				errx(13, "mmap (anonymous memory) failed");
		}
	}
	fsi = fi;
	fso = fo;
	if (Oflag) {
		sblock.fs_inodefmt = FS_42INODEFMT;
		sblock.fs_maxsymlinklen = 0;
	} else {
		sblock.fs_inodefmt = FS_44INODEFMT;
		sblock.fs_maxsymlinklen = MAXSYMLINKLEN;
	}
	if (Uflag)
		sblock.fs_flags |= FS_DOSOFTDEP;
	if (Lflag)
		strlcpy(sblock.fs_volname, volumelabel, MAXVOLLEN);

	/*
	 * Validate the given file system size.
	 * Verify that its last block can actually be accessed.
	 */
	if (fssize == 0)
		printf("preposterous size %lu\n", fssize), exit(13);
	wtfs(fssize - (realsectorsize / DEV_BSIZE), realsectorsize,
		 (char *)&sblock);
	/*
	 * collect and verify the sector and track info
	 */
	sblock.fs_nsect = nsectors;
	sblock.fs_ntrak = ntracks;
	if (sblock.fs_ntrak <= 0)
		printf("preposterous ntrak %d\n", sblock.fs_ntrak), exit(14);
	if (sblock.fs_nsect <= 0)
		printf("preposterous nsect %d\n", sblock.fs_nsect), exit(15);
	/*
	 * collect and verify the filesystem density info
	 */
	sblock.fs_avgfilesize = avgfilesize;
	sblock.fs_avgfpdir = avgfilesperdir;
	if (sblock.fs_avgfilesize <= 0)
		printf("illegal expected average file size %d\n",
		    sblock.fs_avgfilesize), exit(14);
	if (sblock.fs_avgfpdir <= 0)
		printf("illegal expected number of files per directory %d\n",
		    sblock.fs_avgfpdir), exit(15);
	/*
	 * collect and verify the block and fragment sizes
	 */
	sblock.fs_bsize = bsize;
	sblock.fs_fsize = fsize;
	if (!POWEROF2(sblock.fs_bsize)) {
		printf("block size must be a power of 2, not %d\n",
		    sblock.fs_bsize);
		exit(16);
	}
	if (!POWEROF2(sblock.fs_fsize)) {
		printf("fragment size must be a power of 2, not %d\n",
		    sblock.fs_fsize);
		exit(17);
	}
	if (sblock.fs_fsize < sectorsize) {
		printf("fragment size %d is too small, minimum is %d\n",
		    sblock.fs_fsize, sectorsize);
		exit(18);
	}
	if (sblock.fs_bsize < MINBSIZE) {
		printf("block size %d is too small, minimum is %d\n",
		    sblock.fs_bsize, MINBSIZE);
		exit(19);
	}
	if (sblock.fs_bsize < sblock.fs_fsize) {
		printf("block size (%d) cannot be smaller than fragment size (%d)\n",
		    sblock.fs_bsize, sblock.fs_fsize);
		exit(20);
	}
	sblock.fs_bmask = ~(sblock.fs_bsize - 1);
	sblock.fs_fmask = ~(sblock.fs_fsize - 1);
	sblock.fs_qbmask = ~sblock.fs_bmask;
	sblock.fs_qfmask = ~sblock.fs_fmask;
	for (sblock.fs_bshift = 0, i = sblock.fs_bsize; i > 1; i >>= 1)
		sblock.fs_bshift++;
	for (sblock.fs_fshift = 0, i = sblock.fs_fsize; i > 1; i >>= 1)
		sblock.fs_fshift++;
	sblock.fs_frag = numfrags(&sblock, sblock.fs_bsize);
	for (sblock.fs_fragshift = 0, i = sblock.fs_frag; i > 1; i >>= 1)
		sblock.fs_fragshift++;
	if (sblock.fs_frag > MAXFRAG) {
		printf("fragment size %d is too small, minimum with block size %d is %d\n",
		    sblock.fs_fsize, sblock.fs_bsize,
		    sblock.fs_bsize / MAXFRAG);
		exit(21);
	}
	sblock.fs_nrpos = nrpos;
	sblock.fs_nindir = sblock.fs_bsize / sizeof(daddr_t);
	sblock.fs_inopb = sblock.fs_bsize / sizeof(struct ufs1_dinode);
	sblock.fs_nspf = sblock.fs_fsize / sectorsize;
	for (sblock.fs_fsbtodb = 0, i = NSPF(&sblock); i > 1; i >>= 1)
		sblock.fs_fsbtodb++;
	sblock.fs_sblkno =
	    roundup(howmany(bbsize + sbsize, sblock.fs_fsize), sblock.fs_frag);
	sblock.fs_cblkno = (daddr_t)(sblock.fs_sblkno +
	    roundup(howmany(sbsize, sblock.fs_fsize), sblock.fs_frag));
	sblock.fs_iblkno = sblock.fs_cblkno + sblock.fs_frag;
	sblock.fs_cgoffset = roundup(
	    howmany(sblock.fs_nsect, NSPF(&sblock)), sblock.fs_frag);
	for (sblock.fs_cgmask = 0xffffffff, i = sblock.fs_ntrak; i > 1; i >>= 1)
		sblock.fs_cgmask <<= 1;
	if (!POWEROF2(sblock.fs_ntrak))
		sblock.fs_cgmask <<= 1;
	sblock.fs_maxfilesize = sblock.fs_bsize * NDADDR - 1;
	for (sizepb = sblock.fs_bsize, i = 0; i < NIADDR; i++) {
		sizepb *= NINDIR(&sblock);
		sblock.fs_maxfilesize += sizepb;
	}
	/*
	 * Validate specified/determined secpercyl
	 * and calculate minimum cylinders per group.
	 */
	sblock.fs_spc = secpercyl;
	for (sblock.fs_cpc = NSPB(&sblock), i = sblock.fs_spc;
	     sblock.fs_cpc > 1 && (i & 1) == 0;
	     sblock.fs_cpc >>= 1, i >>= 1)
		/* void */;
	mincpc = sblock.fs_cpc;
	bpcg = sblock.fs_spc * sectorsize;
	inospercg = roundup(bpcg / sizeof(struct ufs1_dinode), INOPB(&sblock));
	if (inospercg > MAXIPG(&sblock))
		inospercg = MAXIPG(&sblock);
	used = (sblock.fs_iblkno + inospercg / INOPF(&sblock)) * NSPF(&sblock);
	mincpgcnt = howmany(sblock.fs_cgoffset * (~sblock.fs_cgmask) + used,
	    sblock.fs_spc);
	mincpg = roundup(mincpgcnt, mincpc);
	/*
	 * Ensure that cylinder group with mincpg has enough space
	 * for block maps.
	 */
	sblock.fs_cpg = mincpg;
	sblock.fs_ipg = inospercg;
	if (maxcontig > 1)
		sblock.fs_contigsumsize = MIN(maxcontig, FS_MAXCONTIG);
	mapcramped = 0;
	while (CGSIZE(&sblock) > (uint32_t)sblock.fs_bsize) {
		mapcramped = 1;
		if (sblock.fs_bsize < MAXBSIZE) {
			sblock.fs_bsize <<= 1;
			if ((i & 1) == 0) {
				i >>= 1;
			} else {
				sblock.fs_cpc <<= 1;
				mincpc <<= 1;
				mincpg = roundup(mincpgcnt, mincpc);
				sblock.fs_cpg = mincpg;
			}
			sblock.fs_frag <<= 1;
			sblock.fs_fragshift += 1;
			if (sblock.fs_frag <= MAXFRAG)
				continue;
		}
		if (sblock.fs_fsize == sblock.fs_bsize) {
			printf("There is no block size that");
			printf(" can support this disk\n");
			exit(22);
		}
		sblock.fs_frag >>= 1;
		sblock.fs_fragshift -= 1;
		sblock.fs_fsize <<= 1;
		sblock.fs_nspf <<= 1;
	}
	/*
	 * Ensure that cylinder group with mincpg has enough space for inodes.
	 */
	inodecramped = 0;
	inospercg = calcipg(mincpg, bpcg, &usedb);
	sblock.fs_ipg = inospercg;
	while (inospercg > MAXIPG(&sblock)) {
		inodecramped = 1;
		if (mincpc == 1 || sblock.fs_frag == 1 ||
		    sblock.fs_bsize == MINBSIZE)
			break;
		printf("With a block size of %d %s %d\n", sblock.fs_bsize,
		       "minimum bytes per inode is",
		       (int)((mincpg * (off_t)bpcg - usedb)
			     / MAXIPG(&sblock) + 1));
		sblock.fs_bsize >>= 1;
		sblock.fs_frag >>= 1;
		sblock.fs_fragshift -= 1;
		mincpc >>= 1;
		sblock.fs_cpg = roundup(mincpgcnt, mincpc);
		if (CGSIZE(&sblock) > (uint32_t)sblock.fs_bsize) {
			sblock.fs_bsize <<= 1;
			break;
		}
		mincpg = sblock.fs_cpg;
		inospercg = calcipg(mincpg, bpcg, &usedb);
		sblock.fs_ipg = inospercg;
	}
	if (inodecramped) {
		if (inospercg > MAXIPG(&sblock)) {
			printf("Minimum bytes per inode is %d\n",
			       (int)((mincpg * (off_t)bpcg - usedb)
				     / MAXIPG(&sblock) + 1));
		} else if (!mapcramped) {
			printf("With %d bytes per inode, ", density);
			printf("minimum cylinders per group is %ld\n", mincpg);
		}
	}
	if (mapcramped) {
		printf("With %d sectors per cylinder, ", sblock.fs_spc);
		printf("minimum cylinders per group is %ld\n", mincpg);
	}
	if (inodecramped || mapcramped) {
		if (sblock.fs_bsize != bsize)
			printf("%s to be changed from %d to %d\n",
			    "This requires the block size",
			    bsize, sblock.fs_bsize);
		if (sblock.fs_fsize != fsize)
			printf("\t%s to be changed from %d to %d\n",
			    "and the fragment size",
			    fsize, sblock.fs_fsize);
		exit(23);
	}
	/*
	 * Calculate the number of cylinders per group
	 */
	sblock.fs_cpg = cpg;
	if (sblock.fs_cpg % mincpc != 0) {
		printf("%s groups must have a multiple of %ld cylinders\n",
			cpgflg ? "Cylinder" : "Warning: cylinder", mincpc);
		sblock.fs_cpg = roundup(sblock.fs_cpg, mincpc);
		if (!cpgflg)
			cpg = sblock.fs_cpg;
	}
	/*
	 * Must ensure there is enough space for inodes.
	 */
	sblock.fs_ipg = calcipg(sblock.fs_cpg, bpcg, &usedb);
	while (sblock.fs_ipg > MAXIPG(&sblock)) {
		inodecramped = 1;
		sblock.fs_cpg -= mincpc;
		sblock.fs_ipg = calcipg(sblock.fs_cpg, bpcg, &usedb);
	}
	/*
	 * Must ensure there is enough space to hold block map.
	 */
	while (CGSIZE(&sblock) > (uint32_t)sblock.fs_bsize) {
		mapcramped = 1;
		sblock.fs_cpg -= mincpc;
		sblock.fs_ipg = calcipg(sblock.fs_cpg, bpcg, &usedb);
	}
	sblock.fs_fpg = (sblock.fs_cpg * sblock.fs_spc) / NSPF(&sblock);
	if ((sblock.fs_cpg * sblock.fs_spc) % NSPB(&sblock) != 0) {
		printf("panic (fs_cpg * fs_spc) %% NSPF != 0");
		exit(24);
	}
	if (sblock.fs_cpg < mincpg) {
		printf("cylinder groups must have at least %ld cylinders\n",
			mincpg);
		exit(25);
	} else if (sblock.fs_cpg != cpg) {
		if (!cpgflg && !mfs)
			printf("Warning: ");
		else if (!mapcramped && !inodecramped)
			exit(26);
		if (!mfs) {
		    if (mapcramped && inodecramped)
			printf("Block size and bytes per inode restrict");
		    else if (mapcramped)
			printf("Block size restricts");
		    else
			printf("Bytes per inode restrict");
		    printf(" cylinders per group to %d.\n", sblock.fs_cpg);
		}
		if (cpgflg)
			exit(27);
	}
	sblock.fs_cgsize = fragroundup(&sblock, CGSIZE(&sblock));
	/*
	 * Now have size for file system and nsect and ntrak.
	 * Determine number of cylinders and blocks in the file system.
	 */
	sblock.fs_size = fssize = dbtofsb(&sblock, fssize);
	sblock.fs_ncyl = fssize * NSPF(&sblock) / sblock.fs_spc;
	if ((long)fssize * NSPF(&sblock) > sblock.fs_ncyl * sblock.fs_spc) {
		sblock.fs_ncyl++;
		emitwarn = 1;
	}
	if (sblock.fs_ncyl < 1) {
		printf("file systems must have at least one cylinder\n");
		exit(28);
	}
	/*
	 * Determine feasability/values of rotational layout tables.
	 *
	 * The size of the rotational layout tables is limited by the
	 * size of the superblock, SBSIZE. The amount of space available
	 * for tables is calculated as (SBSIZE - sizeof (struct fs)).
	 * The size of these tables is inversely proportional to the block
	 * size of the file system. The size increases if sectors per track
	 * are not powers of two, because more cylinders must be described
	 * by the tables before the rotational pattern repeats (fs_cpc).
	 */
	sblock.fs_interleave = interleave;
	sblock.fs_trackskew = trackskew;
	sblock.fs_npsect = nphyssectors;
	sblock.fs_postblformat = FS_DYNAMICPOSTBLFMT;
	sblock.fs_sbsize = fragroundup(&sblock, sizeof(struct fs));
	if (sblock.fs_sbsize > SBSIZE)
		sblock.fs_sbsize = SBSIZE;
	if (sblock.fs_ntrak == 1) {
		sblock.fs_cpc = 0;
		goto next;
	}
	postblsize = sblock.fs_nrpos * sblock.fs_cpc * sizeof(int16_t);
	rotblsize = sblock.fs_cpc * sblock.fs_spc / NSPB(&sblock);
	totalsbsize = sizeof(struct fs) + rotblsize;
	if (sblock.fs_nrpos == 8 && sblock.fs_cpc <= 16) {
		/* use old static table space */
		sblock.fs_postbloff = (char *)(&sblock.fs_opostbl[0][0]) -
		    (char *)(&sblock.fs_firstfield);
		sblock.fs_rotbloff = &sblock.fs_space[0] -
		    (u_char *)(&sblock.fs_firstfield);
	} else {
		/* use dynamic table space */
		sblock.fs_postbloff = &sblock.fs_space[0] -
		    (u_char *)(&sblock.fs_firstfield);
		sblock.fs_rotbloff = sblock.fs_postbloff + postblsize;
		totalsbsize += postblsize;
	}
	if (totalsbsize > SBSIZE ||
	    sblock.fs_nsect > (1 << NBBY) * NSPB(&sblock)) {
		printf("%s %s %d %s %d.%s",
		    "Warning: insufficient space in super block for\n",
		    "rotational layout tables with nsect", sblock.fs_nsect,
		    "and ntrak", sblock.fs_ntrak,
		    "\nFile system performance may be impaired.\n");
		sblock.fs_cpc = 0;
		goto next;
	}
	sblock.fs_sbsize = fragroundup(&sblock, totalsbsize);
	if (sblock.fs_sbsize > SBSIZE)
		sblock.fs_sbsize = SBSIZE;
	/*
	 * calculate the available blocks for each rotational position
	 */
	for (cylno = 0; cylno < sblock.fs_cpc; cylno++)
		for (rpos = 0; rpos < sblock.fs_nrpos; rpos++)
			fs_postbl(&sblock, cylno)[rpos] = -1;
	for (i = (rotblsize - 1) * sblock.fs_frag;
	     i >= 0; i -= sblock.fs_frag) {
		cylno = cbtocylno(&sblock, i);
		rpos = cbtorpos(&sblock, i);
		blk = fragstoblks(&sblock, i);
		if (fs_postbl(&sblock, cylno)[rpos] == -1)
			fs_rotbl(&sblock)[blk] = 0;
		else
			fs_rotbl(&sblock)[blk] =
			    fs_postbl(&sblock, cylno)[rpos] - blk;
		fs_postbl(&sblock, cylno)[rpos] = blk;
	}
next:
	/*
	 * Compute/validate number of cylinder groups.
	 */
	sblock.fs_ncg = sblock.fs_ncyl / sblock.fs_cpg;
	if (sblock.fs_ncyl % sblock.fs_cpg)
		sblock.fs_ncg++;
	sblock.fs_dblkno = sblock.fs_iblkno + sblock.fs_ipg / INOPF(&sblock);
	i = MIN(~sblock.fs_cgmask, sblock.fs_ncg - 1);
	if (cgdmin(&sblock, i) - cgbase(&sblock, i) >= sblock.fs_fpg) {
		printf("inode blocks/cyl group (%ld) >= data blocks (%ld)\n",
		    cgdmin(&sblock, i) - cgbase(&sblock, i) / sblock.fs_frag,
		    (long)(sblock.fs_fpg / sblock.fs_frag));
		printf("number of cylinders per cylinder group (%d) %s.\n",
		    sblock.fs_cpg, "must be increased");
		exit(29);
	}
	j = sblock.fs_ncg - 1;
	if ((i = fssize - j * sblock.fs_fpg) < sblock.fs_fpg &&
	    cgdmin(&sblock, j) - cgbase(&sblock, j) > i) {
		if (j == 0) {
			printf("Filesystem must have at least %d sectors\n",
			    NSPF(&sblock) *
			    (cgdmin(&sblock, 0) + 3 * sblock.fs_frag));
			exit(30);
		}
		printf(
"Warning: inode blocks/cyl group (%ld) >= data blocks (%ld) in last\n",
		    (cgdmin(&sblock, j) - cgbase(&sblock, j)) / sblock.fs_frag,
		    i / sblock.fs_frag);
		printf(
"    cylinder group. This implies %ld sector(s) cannot be allocated.\n",
		    i * NSPF(&sblock));
		sblock.fs_ncg--;
		sblock.fs_ncyl -= sblock.fs_ncyl % sblock.fs_cpg;
		sblock.fs_size = fssize = sblock.fs_ncyl * sblock.fs_spc /
		    NSPF(&sblock);
		emitwarn = 0;
	}
	if (emitwarn && !mfs) {
		printf("Warning: %lu sector(s) in last cylinder unallocated\n",
		    sblock.fs_spc -
		    (fssize * NSPF(&sblock) - (sblock.fs_ncyl - 1)
		    * sblock.fs_spc));
	}
	/*
	 * fill in remaining fields of the super block
	 */
	sblock.fs_csaddr = cgdmin(&sblock, 0);
	sblock.fs_cssize =
	    fragroundup(&sblock, sblock.fs_ncg * sizeof(struct csum));
	/*
	 * The superblock fields 'fs_csmask' and 'fs_csshift' are no
	 * longer used. However, we still initialise them so that the
	 * filesystem remains compatible with old kernels.
	 */
	i = sblock.fs_bsize / sizeof(struct csum);
	sblock.fs_csmask = ~(i - 1);
	for (sblock.fs_csshift = 0; i > 1; i >>= 1)
		sblock.fs_csshift++;
	fscs = (struct csum *)calloc(1, sblock.fs_cssize);
	if (fscs == NULL)
		errx(31, "calloc failed");
	sblock.fs_magic = FS_MAGIC;
	sblock.fs_rotdelay = rotdelay;
	sblock.fs_minfree = minfree;
	sblock.fs_maxcontig = maxcontig;
	sblock.fs_maxbpg = maxbpg;
	sblock.fs_rps = rpm / 60;
	sblock.fs_optim = opt;
	sblock.fs_cgrotor = 0;
	sblock.fs_cstotal.cs_ndir = 0;
	sblock.fs_cstotal.cs_nbfree = 0;
	sblock.fs_cstotal.cs_nifree = 0;
	sblock.fs_cstotal.cs_nffree = 0;
	sblock.fs_fmod = 0;
	sblock.fs_ronly = 0;
	sblock.fs_clean = 1;
#ifdef FSIRAND
	sblock.fs_id[0] = (long)utime;
	sblock.fs_id[1] = random();
#endif

	/*
	 * Dump out summary information about file system.
	 */
	if (!mfs) {
		printf("%s:\t%d sectors in %d %s of %d tracks, %d sectors\n",
		    fsys, sblock.fs_size * NSPF(&sblock), sblock.fs_ncyl,
		    "cylinders", sblock.fs_ntrak, sblock.fs_nsect);
#define B2MBFACTOR (1 / (1024.0 * 1024.0))
		printf("\t%.1fMB in %d cyl groups (%d c/g, %.2fMB/g, %d i/g)%s\n",
		    (float)sblock.fs_size * sblock.fs_fsize * B2MBFACTOR,
		    sblock.fs_ncg, sblock.fs_cpg,
		    (float)sblock.fs_fpg * sblock.fs_fsize * B2MBFACTOR,
		    sblock.fs_ipg,
			sblock.fs_flags & FS_DOSOFTDEP ? " SOFTUPDATES" : "");
#undef B2MBFACTOR
	}
	
	if (Eflag && !Nflag) {
		printf("Erasing sectors [%"PRIu64" --- %"PRIu64"]\n",
		    (SBOFF + slice_offset) / sectorsize,
		    fsbtodb(&sblock,sblock.fs_size) -
		    ((SBOFF + slice_offset) / sectorsize) - 1);
		erfs(SBOFF + slice_offset, (fsbtodb(&sblock,sblock.fs_size) -
		    ((SBOFF + slice_offset)/ sectorsize) - 1) *
		    (unsigned long long)sectorsize);
	}
	/*
	 * Now build the cylinders group blocks and
	 * then print out indices of cylinder groups.
	 */
	if (!mfs)
		printf("super-block backups (for fsck -b #) at:\n");
	i = 0;
	width = charsperline();
	for (cylno = 0; cylno < sblock.fs_ncg; cylno++) {
		initcg(cylno, utime);
		if (mfs)
			continue;
		j = snprintf(tmpbuf, sizeof(tmpbuf), " %ld%s",
		    fsbtodb(&sblock, cgsblock(&sblock, cylno)),
		    cylno < (sblock.fs_ncg-1) ? "," : "" );
		if (i + j >= width) {
			printf("\n");
			i = 0;
		}
		i += j;
		printf("%s", tmpbuf);
		fflush(stdout);
	}
	if (!mfs)
		printf("\n");
	if (Nflag && !mfs)
		exit(0);
	/*
	 * Now construct the initial file system,
	 * then write out the super-block.
	 */
	fsinit(utime);
	sblock.fs_time = utime;
	wtfs((int)SBOFF / sectorsize, sbsize, (char *)&sblock);
	for (i = 0; i < sblock.fs_cssize; i += sblock.fs_bsize)
		wtfs(fsbtodb(&sblock, sblock.fs_csaddr + numfrags(&sblock, i)),
			sblock.fs_cssize - i < sblock.fs_bsize ?
			    sblock.fs_cssize - i : sblock.fs_bsize,
			((char *)fscs) + i);
	/*
	 * Write out the duplicate super blocks
	 */
	for (cylno = 0; cylno < sblock.fs_ncg; cylno++)
		wtfs(fsbtodb(&sblock, cgsblock(&sblock, cylno)),
		    sbsize, (char *)&sblock);
	wtfsflush();

	/*
	 * NOTE: we no longer update information in the disklabel
	 */

	/*
	 * Notify parent process of success.
	 * Dissociate from session and tty.
	 *
	 * NOTE: We are the child and may receive a SIGINT due
	 *	 to losing the tty session? XXX
	 */
	if (mfs) {
		/* YYY */
		kill(mfs_ppid, SIGUSR1);
		setsid();
		close(0);
		close(1);
		close(2);
		chdir("/");
		/* returns to mount_mfs (newfs) and issues the mount */
	}
}

/*
 * Initialize a cylinder group.
 */
void
initcg(int cylno, time_t utime)
{
	daddr_t cbase, d, dlower, dupper, dmax, blkno;
	long i;
	unsigned long k;
	struct csum *cs;
#ifdef FSIRAND
	uint32_t j;
#endif

	/*
	 * Determine block bounds for cylinder group.
	 * Allow space for super block summary information in first
	 * cylinder group.
	 */
	cbase = cgbase(&sblock, cylno);
	dmax = cbase + sblock.fs_fpg;
	if (dmax > sblock.fs_size)
		dmax = sblock.fs_size;
	dlower = cgsblock(&sblock, cylno) - cbase;
	dupper = cgdmin(&sblock, cylno) - cbase;
	if (cylno == 0)
		dupper += howmany(sblock.fs_cssize, sblock.fs_fsize);
	cs = fscs + cylno;
	memset(&acg, 0, sblock.fs_cgsize);
	acg.cg_time = utime;
	acg.cg_magic = CG_MAGIC;
	acg.cg_cgx = cylno;
	if (cylno == sblock.fs_ncg - 1)
		acg.cg_ncyl = sblock.fs_ncyl % sblock.fs_cpg;
	else
		acg.cg_ncyl = sblock.fs_cpg;
	acg.cg_niblk = sblock.fs_ipg;
	acg.cg_ndblk = dmax - cbase;
	if (sblock.fs_contigsumsize > 0)
		acg.cg_nclusterblks = acg.cg_ndblk / sblock.fs_frag;
	acg.cg_btotoff = &acg.cg_space[0] - (u_char *)(&acg.cg_firstfield);
	acg.cg_boff = acg.cg_btotoff + sblock.fs_cpg * sizeof(int32_t);
	acg.cg_iusedoff = acg.cg_boff +
		sblock.fs_cpg * sblock.fs_nrpos * sizeof(u_int16_t);
	acg.cg_freeoff = acg.cg_iusedoff + howmany(sblock.fs_ipg, NBBY);
	if (sblock.fs_contigsumsize <= 0) {
		acg.cg_nextfreeoff = acg.cg_freeoff +
		   howmany(sblock.fs_cpg * sblock.fs_spc / NSPF(&sblock), NBBY);
	} else {
		acg.cg_clustersumoff = acg.cg_freeoff + howmany
		    (sblock.fs_cpg * sblock.fs_spc / NSPF(&sblock), NBBY) -
		    sizeof(u_int32_t);
		acg.cg_clustersumoff =
		    roundup(acg.cg_clustersumoff, sizeof(u_int32_t));
		acg.cg_clusteroff = acg.cg_clustersumoff +
		    (sblock.fs_contigsumsize + 1) * sizeof(u_int32_t);
		acg.cg_nextfreeoff = acg.cg_clusteroff + howmany
		    (sblock.fs_cpg * sblock.fs_spc / NSPB(&sblock), NBBY);
	}
	if (acg.cg_nextfreeoff - (long)(&acg.cg_firstfield) > sblock.fs_cgsize) {
		printf("Panic: cylinder group too big\n");
		exit(37);
	}
	acg.cg_cs.cs_nifree += sblock.fs_ipg;
	if (cylno == 0) {
		for (k = 0; k < ROOTINO; k++) {
			setbit(cg_inosused(&acg), k);
			acg.cg_cs.cs_nifree--;
		}
	}
	for (i = 0; i < sblock.fs_ipg / INOPF(&sblock); i += sblock.fs_frag) {
#ifdef FSIRAND
		for (j = 0;
		     j < sblock.fs_bsize / sizeof(struct ufs1_dinode);
		     j++) {
			zino[j].di_gen = random();
		}
#endif
		wtfs(fsbtodb(&sblock, cgimin(&sblock, cylno) + i),
		    sblock.fs_bsize, (char *)zino);
	}
	if (cylno > 0) {
		/*
		 * In cylno 0, beginning space is reserved
		 * for boot and super blocks.
		 */
		for (d = 0; d < dlower; d += sblock.fs_frag) {
			blkno = d / sblock.fs_frag;
			setblock(&sblock, cg_blksfree(&acg), blkno);
			if (sblock.fs_contigsumsize > 0)
				setbit(cg_clustersfree(&acg), blkno);
			acg.cg_cs.cs_nbfree++;
			cg_blktot(&acg)[cbtocylno(&sblock, d)]++;
			cg_blks(&sblock, &acg, cbtocylno(&sblock, d))
			    [cbtorpos(&sblock, d)]++;
		}
		sblock.fs_dsize += dlower;
	}
	sblock.fs_dsize += acg.cg_ndblk - dupper;
	if ((i = dupper % sblock.fs_frag)) {
		acg.cg_frsum[sblock.fs_frag - i]++;
		for (d = dupper + sblock.fs_frag - i; dupper < d; dupper++) {
			setbit(cg_blksfree(&acg), dupper);
			acg.cg_cs.cs_nffree++;
		}
	}
	for (d = dupper; d + sblock.fs_frag <= dmax - cbase; ) {
		blkno = d / sblock.fs_frag;
		setblock(&sblock, cg_blksfree(&acg), blkno);
		if (sblock.fs_contigsumsize > 0)
			setbit(cg_clustersfree(&acg), blkno);
		acg.cg_cs.cs_nbfree++;
		cg_blktot(&acg)[cbtocylno(&sblock, d)]++;
		cg_blks(&sblock, &acg, cbtocylno(&sblock, d))
		    [cbtorpos(&sblock, d)]++;
		d += sblock.fs_frag;
	}
	if (d < dmax - cbase) {
		acg.cg_frsum[dmax - cbase - d]++;
		for (; d < dmax - cbase; d++) {
			setbit(cg_blksfree(&acg), d);
			acg.cg_cs.cs_nffree++;
		}
	}
	if (sblock.fs_contigsumsize > 0) {
		int32_t *sump = cg_clustersum(&acg);
		u_char *mapp = cg_clustersfree(&acg);
		int map = *mapp++;
		int bit = 1;
		int run = 0;

		for (i = 0; i < acg.cg_nclusterblks; i++) {
			if ((map & bit) != 0) {
				run++;
			} else if (run != 0) {
				if (run > sblock.fs_contigsumsize)
					run = sblock.fs_contigsumsize;
				sump[run]++;
				run = 0;
			}
			if ((i & (NBBY - 1)) != (NBBY - 1)) {
				bit <<= 1;
			} else {
				map = *mapp++;
				bit = 1;
			}
		}
		if (run != 0) {
			if (run > sblock.fs_contigsumsize)
				run = sblock.fs_contigsumsize;
			sump[run]++;
		}
	}
	sblock.fs_cstotal.cs_ndir += acg.cg_cs.cs_ndir;
	sblock.fs_cstotal.cs_nffree += acg.cg_cs.cs_nffree;
	sblock.fs_cstotal.cs_nbfree += acg.cg_cs.cs_nbfree;
	sblock.fs_cstotal.cs_nifree += acg.cg_cs.cs_nifree;
	*cs = acg.cg_cs;
	wtfs(fsbtodb(&sblock, cgtod(&sblock, cylno)),
		sblock.fs_bsize, (char *)&acg);
}

/*
 * initialize the file system
 */
struct ufs1_dinode node;

#ifdef LOSTDIR
#define PREDEFDIR 3
#else
#define PREDEFDIR 2
#endif

struct direct root_dir[] = {
	{ ROOTINO, sizeof(struct direct), DT_DIR, 1, "." },
	{ ROOTINO, sizeof(struct direct), DT_DIR, 2, ".." },
#ifdef LOSTDIR
	{ LOSTFOUNDINO, sizeof(struct direct), DT_DIR, 10, "lost+found" },
#endif
};
struct odirect {
	u_long	d_ino;
	u_short	d_reclen;
	u_short	d_namlen;
	u_char	d_name[MAXNAMLEN + 1];
} oroot_dir[] = {
	{ ROOTINO, sizeof(struct direct), 1, "." },
	{ ROOTINO, sizeof(struct direct), 2, ".." },
#ifdef LOSTDIR
	{ LOSTFOUNDINO, sizeof(struct direct), 10, "lost+found" },
#endif
};
#ifdef LOSTDIR
struct direct lost_found_dir[] = {
	{ LOSTFOUNDINO, sizeof(struct direct), DT_DIR, 1, "." },
	{ ROOTINO, sizeof(struct direct), DT_DIR, 2, ".." },
	{ 0, DIRBLKSIZ, 0, 0, 0 },
};
struct odirect olost_found_dir[] = {
	{ LOSTFOUNDINO, sizeof(struct direct), 1, "." },
	{ ROOTINO, sizeof(struct direct), 2, ".." },
	{ 0, DIRBLKSIZ, 0, 0 },
};
#endif
char buf[MAXBSIZE];

void
fsinit(time_t utime)
{
#ifdef LOSTDIR
	int i;
#endif

	/*
	 * initialize the node
	 */
	node.di_atime = utime;
	node.di_mtime = utime;
	node.di_ctime = utime;
#ifdef LOSTDIR
	/*
	 * create the lost+found directory
	 */
	if (Oflag) {
		makedir((struct direct *)olost_found_dir, 2);
		for (i = DIRBLKSIZ; i < sblock.fs_bsize; i += DIRBLKSIZ)
			memmove(&buf[i], &olost_found_dir[2],
			    DIRSIZ(0, &olost_found_dir[2]));
	} else {
		makedir(lost_found_dir, 2);
		for (i = DIRBLKSIZ; i < sblock.fs_bsize; i += DIRBLKSIZ)
			memmove(&buf[i], &lost_found_dir[2],
			    DIRSIZ(0, &lost_found_dir[2]));
	}
	node.di_mode = IFDIR | UMASK;
	node.di_nlink = 2;
	node.di_size = sblock.fs_bsize;
	node.di_db[0] = alloc(node.di_size, node.di_mode);
	node.di_blocks = btodb(fragroundup(&sblock, node.di_size));
	wtfs(fsbtodb(&sblock, node.di_db[0]), node.di_size, buf);
	iput(&node, LOSTFOUNDINO);
#endif
	/*
	 * create the root directory
	 */
	if (mfs)
		node.di_mode = IFDIR | 01777;
	else
		node.di_mode = IFDIR | UMASK;
	node.di_nlink = PREDEFDIR;
	if (Oflag)
		node.di_size = makedir((struct direct *)oroot_dir, PREDEFDIR);
	else
		node.di_size = makedir(root_dir, PREDEFDIR);
	node.di_db[0] = alloc(sblock.fs_fsize, node.di_mode);
	node.di_blocks = btodb(fragroundup(&sblock, node.di_size));
	wtfs(fsbtodb(&sblock, node.di_db[0]), sblock.fs_fsize, buf);
	iput(&node, ROOTINO);
}

/*
 * construct a set of directory entries in "buf".
 * return size of directory.
 */
int
makedir(struct direct *protodir, int entries)
{
	char *cp;
	int i, spcleft;

	spcleft = DIRBLKSIZ;
	for (cp = buf, i = 0; i < entries - 1; i++) {
		protodir[i].d_reclen = DIRSIZ(0, &protodir[i]);
		memmove(cp, &protodir[i], protodir[i].d_reclen);
		cp += protodir[i].d_reclen;
		spcleft -= protodir[i].d_reclen;
	}
	protodir[i].d_reclen = spcleft;
	memmove(cp, &protodir[i], DIRSIZ(0, &protodir[i]));
	return (DIRBLKSIZ);
}

/*
 * allocate a block or frag
 */
daddr_t
alloc(int size, int mode)
{
	int i, frag;
	daddr_t d, blkno;

	rdfs(fsbtodb(&sblock, cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	if (acg.cg_magic != CG_MAGIC) {
		printf("cg 0: bad magic number\n");
		return (0);
	}
	if (acg.cg_cs.cs_nbfree == 0) {
		printf("first cylinder group ran out of space\n");
		return (0);
	}
	for (d = 0; d < acg.cg_ndblk; d += sblock.fs_frag)
		if (isblock(&sblock, cg_blksfree(&acg), d / sblock.fs_frag))
			goto goth;
	printf("internal error: can't find block in cyl 0\n");
	return (0);
goth:
	blkno = fragstoblks(&sblock, d);
	clrblock(&sblock, cg_blksfree(&acg), blkno);
	if (sblock.fs_contigsumsize > 0)
		clrbit(cg_clustersfree(&acg), blkno);
	acg.cg_cs.cs_nbfree--;
	sblock.fs_cstotal.cs_nbfree--;
	fscs[0].cs_nbfree--;
	if (mode & IFDIR) {
		acg.cg_cs.cs_ndir++;
		sblock.fs_cstotal.cs_ndir++;
		fscs[0].cs_ndir++;
	}
	cg_blktot(&acg)[cbtocylno(&sblock, d)]--;
	cg_blks(&sblock, &acg, cbtocylno(&sblock, d))[cbtorpos(&sblock, d)]--;
	if (size != sblock.fs_bsize) {
		frag = howmany(size, sblock.fs_fsize);
		fscs[0].cs_nffree += sblock.fs_frag - frag;
		sblock.fs_cstotal.cs_nffree += sblock.fs_frag - frag;
		acg.cg_cs.cs_nffree += sblock.fs_frag - frag;
		acg.cg_frsum[sblock.fs_frag - frag]++;
		for (i = frag; i < sblock.fs_frag; i++)
			setbit(cg_blksfree(&acg), d + i);
	}
	wtfs(fsbtodb(&sblock, cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	return (d);
}

/*
 * Calculate number of inodes per group.
 */
long
calcipg(long cylspg, long bpcg, off_t *usedbp)
{
	int i;
	long ipg, new_ipg, ncg, ncyl;
	off_t usedb;

	/*
	 * Prepare to scale by fssize / (number of sectors in cylinder groups).
	 * Note that fssize is still in sectors, not filesystem blocks.
	 */
	ncyl = howmany(fssize, (u_int)secpercyl);
	ncg = howmany(ncyl, cylspg);
	/*
	 * Iterate a few times to allow for ipg depending on itself.
	 */
	ipg = 0;
	for (i = 0; i < 10; i++) {
		usedb = (sblock.fs_iblkno + ipg / INOPF(&sblock))
			* NSPF(&sblock) * (off_t)sectorsize;
		new_ipg = (cylspg * (quad_t)bpcg - usedb) / density * fssize
			  / ncg / secpercyl / cylspg;
		new_ipg = roundup(new_ipg, INOPB(&sblock));
		if (new_ipg == ipg)
			break;
		ipg = new_ipg;
	}
	*usedbp = usedb;
	return (ipg);
}

/*
 * Allocate an inode on the disk
 */
void
iput(struct ufs1_dinode *ip, ino_t ino)
{
	struct ufs1_dinode inobuf[MAXINOPB];
	daddr_t d;
	int c;

#ifdef FSIRAND
	ip->di_gen = random();
#endif
	c = ino_to_cg(&sblock, ino);
	rdfs(fsbtodb(&sblock, cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	if (acg.cg_magic != CG_MAGIC) {
		printf("cg 0: bad magic number\n");
		exit(31);
	}
	acg.cg_cs.cs_nifree--;
	setbit(cg_inosused(&acg), ino);
	wtfs(fsbtodb(&sblock, cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	sblock.fs_cstotal.cs_nifree--;
	fscs[0].cs_nifree--;
	if (ino >= (uint32_t)sblock.fs_ipg * (uint32_t)sblock.fs_ncg) {
		printf("fsinit: inode value out of range (%ju).\n",
		    (uintmax_t)ino);
		exit(32);
	}
	d = fsbtodb(&sblock, ino_to_fsba(&sblock, ino));
	rdfs(d, sblock.fs_bsize, (char *)inobuf);
	inobuf[ino_to_fsbo(&sblock, ino)] = *ip;
	wtfs(d, sblock.fs_bsize, (char *)inobuf);
}

/*
 * Parent notifies child that it can proceed with the newfs and mount
 * operation (occurs after parent has copied the underlying filesystem
 * if the -C option was specified (for MFS), or immediately after the
 * parent forked the child otherwise).
 */
void
parentready(__unused int signo)
{
  	parentready_signalled = 1;
}

/*
 * Notify parent process that the filesystem has created itself successfully.
 *
 * We have to wait until the mount has actually completed!
 */
void
started(__unused int signo)
{
	int retry = 100;	/* 10 seconds, 100ms */

	while (mfs_ppid && retry) {
		struct stat st;

		if (
		    stat(mfs_mtpt, &st) < 0 ||
		    st.st_dev != mfs_mtstat.st_dev
		) {
			break;
		}
		usleep(100*1000);
		--retry;
	}
	if (retry == 0) {
		fatal("mfs mount failed waiting for mount to go active");
	} else if (copyroot) {
		FSPaste(mfs_mtpt, copyroot, copyhlinks);
	}
	exit(0);
}

/*
 * read a block from the file system
 */
void
rdfs(daddr_t bno, int size, char *bf)
{
	int n;

	wtfsflush();
	if (mfs) {
		memmove(bf, membase + bno * sectorsize, size);
		return;
	}
	if (lseek(fsi, (off_t)bno * sectorsize, 0) < 0) {
		printf("seek error: %ld\n", (long)bno);
		err(33, "rdfs");
	}
	n = read(fsi, bf, size);
	if (n != size) {
		printf("read error: %ld\n", (long)bno);
		err(34, "rdfs");
	}
}

#define WCSIZE (128 * 1024)
daddr_t wc_sect;		/* units of sectorsize */
int wc_end;			/* bytes */
static char wc[WCSIZE];		/* bytes */

/*
 * Flush dirty write behind buffer.
 */
void
wtfsflush(void)
{
	int n;
	if (wc_end) {
		if (lseek(fso, (off_t)wc_sect * sectorsize, SEEK_SET) < 0) {
			printf("seek error: %ld\n", (long)wc_sect);
			err(35, "wtfs - writecombine");
		}
		n = write(fso, wc, wc_end);
		if (n != wc_end) {
			printf("write error: %ld\n", (long)wc_sect);
			err(36, "wtfs - writecombine");
		}
		wc_end = 0;
	}
}

/*
 * Issue ioctl to erase range of sectors using TRIM
 */
void
erfs(off_t byte_start, off_t size)
{
	off_t ioarg[2];
	ioarg[0] = byte_start;
	ioarg[1] = size;
	if (ioctl(fsi, IOCTLTRIM, ioarg) < 0) {
		err(37, "Device trim failed\n");
	}
}

/*
 * write a block to the file system
 */
void
wtfs(daddr_t bno, int size, char *bf)
{
	int n;
	int done;

	if (mfs) {
		memmove(membase + bno * sectorsize, bf, size);
		return;
	}
	if (Nflag)
		return;
	done = 0;
	if (wc_end == 0 && size <= WCSIZE) {
		wc_sect = bno;
		bcopy(bf, wc, size);
		wc_end = size;
		if (wc_end < WCSIZE)
			return;
		done = 1;
	}
	if ((off_t)wc_sect * sectorsize + wc_end == (off_t)bno * sectorsize &&
	    wc_end + size <= WCSIZE) {
		bcopy(bf, wc + wc_end, size);
		wc_end += size;
		if (wc_end < WCSIZE)
			return;
		done = 1;
	}
	wtfsflush();
	if (done)
		return;
	if (lseek(fso, (off_t)bno * sectorsize, SEEK_SET) < 0) {
		printf("seek error: %ld\n", (long)bno);
		err(35, "wtfs");
	}
	n = write(fso, bf, size);
	if (n != size) {
		printf("write error: fso %d blk %ld %d/%d\n", 
			fso, (long)bno, n, size);
		err(36, "wtfs");
	}
}

/*
 * check if a block is available
 */
int
isblock(struct fs *fs, unsigned char *cp, int h)
{
	unsigned char mask;

	switch (fs->fs_frag) {
	case 8:
		return (cp[h] == 0xff);
	case 4:
		mask = 0x0f << ((h & 0x1) << 2);
		return ((cp[h >> 1] & mask) == mask);
	case 2:
		mask = 0x03 << ((h & 0x3) << 1);
		return ((cp[h >> 2] & mask) == mask);
	case 1:
		mask = 0x01 << (h & 0x7);
		return ((cp[h >> 3] & mask) == mask);
	default:
		fprintf(stderr, "isblock bad fs_frag %d\n", fs->fs_frag);
		return (0);
	}
}

/*
 * take a block out of the map
 */
void
clrblock(struct fs *fs, unsigned char *cp, int h)
{
	switch ((fs)->fs_frag) {
	case 8:
		cp[h] = 0;
		return;
	case 4:
		cp[h >> 1] &= ~(0x0f << ((h & 0x1) << 2));
		return;
	case 2:
		cp[h >> 2] &= ~(0x03 << ((h & 0x3) << 1));
		return;
	case 1:
		cp[h >> 3] &= ~(0x01 << (h & 0x7));
		return;
	default:
		fprintf(stderr, "clrblock bad fs_frag %d\n", fs->fs_frag);
		return;
	}
}

/*
 * put a block into the map
 */
void
setblock(struct fs *fs, unsigned char *cp, int h)
{
	switch (fs->fs_frag) {
	case 8:
		cp[h] = 0xff;
		return;
	case 4:
		cp[h >> 1] |= (0x0f << ((h & 0x1) << 2));
		return;
	case 2:
		cp[h >> 2] |= (0x03 << ((h & 0x3) << 1));
		return;
	case 1:
		cp[h >> 3] |= (0x01 << (h & 0x7));
		return;
	default:
		fprintf(stderr, "setblock bad fs_frag %d\n", fs->fs_frag);
		return;
	}
}

/*
 * Determine the number of characters in a
 * single line.
 */

static int
charsperline(void)
{
	int columns;
	char *cp;
	struct winsize ws;

	columns = 0;
	if (ioctl(0, TIOCGWINSZ, &ws) != -1)
		columns = ws.ws_col;
	if (columns == 0 && (cp = getenv("COLUMNS")))
		columns = atoi(cp);
	if (columns == 0)
		columns = 80;	/* last resort */
	return columns;
}
