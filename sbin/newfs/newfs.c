/*
 * Copyright (c) 1983, 1989, 1993, 1994
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
 * @(#) Copyright (c) 1983, 1989, 1993, 1994 The Regents of the University of California.  All rights reserved.
 * @(#)newfs.c	8.13 (Berkeley) 5/1/95
 * $FreeBSD: src/sbin/newfs/newfs.c,v 1.30.2.9 2003/05/13 12:03:55 joerg Exp $
 * $DragonFly: src/sbin/newfs/newfs.c,v 1.17 2007/06/19 19:18:20 dillon Exp $
 */

/*
 * newfs: friendly front end to mkfs
 */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/diskslice.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/sysctl.h>

#include <vfs/ufs/dir.h>
#include <vfs/ufs/dinode.h>
#include <vfs/ufs/fs.h>
#include <vfs/ufs/ufsmount.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <disktab.h>

#ifdef MFS
#include <sys/types.h>
#include <sys/mman.h>
#endif

#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "mntopts.h"
#include "defs.h"

struct mntopt mopts[] = {
	MOPT_STDOPTS,
	MOPT_ASYNC,
	MOPT_NULL,
};

void	fatal(const char *fmt, ...) __printflike(1, 2);

#define	COMPAT			/* allow non-labeled disks */

/*
 * The following two constants set the default block and fragment sizes.
 * Both constants must be a power of 2 and meet the following constraints:
 *	MINBSIZE <= DESBLKSIZE <= MAXBSIZE
 *	sectorsize <= DESFRAGSIZE <= DESBLKSIZE
 *	DESBLKSIZE / DESFRAGSIZE <= 8
 */
#define	DFL_FRAGSIZE	2048
#define	DFL_BLKSIZE	16384

/*
 * Cylinder groups may have up to many cylinders. The actual
 * number used depends upon how much information can be stored
 * on a single cylinder. The default is to use as many as possible
 * cylinders per group.
 */
#define	DESCPG		65536	/* desired fs_cpg ("infinity") */

/*
 * Once upon a time...
 *    ROTDELAY gives the minimum number of milliseconds to initiate
 *    another disk transfer on the same cylinder. It is used in
 *    determining the rotationally optimal layout for disk blocks
 *    within a file; the default of fs_rotdelay is 4ms.
 *
 * ...but now we make this 0 to disable the rotdelay delay because
 * modern drives with read/write-behind achieve higher performance
 * without the delay.
 */
#define ROTDELAY	0

/*
 * MAXBLKPG determines the maximum number of data blocks which are
 * placed in a single cylinder group. The default is one indirect
 * block worth of data blocks.
 */
#define MAXBLKPG(bsize)	((bsize) / sizeof(daddr_t))

/*
 * Each file system has a number of inodes statically allocated.
 * We allocate one inode slot per NFPI fragments, expecting this
 * to be far more than we will ever need.
 */
#define	NFPI		4

/*
 * Once upon a time...
 *    For each cylinder we keep track of the availability of blocks at different
 *    rotational positions, so that we can lay out the data to be picked
 *    up with minimum rotational latency.  NRPOS is the default number of
 *    rotational positions that we distinguish.  With NRPOS of 8 the resolution
 *    of our summary information is 2ms for a typical 3600 rpm drive.
 *
 * ...but now we make this 1 (which essentially disables the rotational
 * position table because modern drives with read-ahead and write-behind do
 * better without the rotational position table.
 */
#define	NRPOS		1	/* number distinct rotational positions */

/*
 * About the same time as the above, we knew what went where on the disks.
 * no longer so, so kill the code which finds the different platters too...
 * We do this by saying one head, with a lot of sectors on it.
 * The number of sectors are used to determine the size of a cyl-group.
 * Kirk suggested one or two meg per "cylinder" so we say two.
 */
#define NTRACKS		1	/* number of heads */
#define NSECTORS	4096	/* number of sectors */

int	mfs;			/* run as the memory based filesystem */
char	*mfs_mtpt;		/* mount point for mfs		*/
struct stat mfs_mtstat;		/* stat prior to mount		*/
int	Lflag;			/* add a volume label */
int	Nflag;			/* run without writing file system */
int	Oflag;			/* format as an 4.3BSD file system */
int	Cflag;			/* copy underlying filesystem (mfs only) */
int	Uflag;			/* enable soft updates for file system */
int	Eflag;			/* erase contents using TRIM */
uint64_t slice_offset;		/* Pysical device slice offset */
u_long	fssize;			/* file system size */
int	ntracks = NTRACKS;	/* # tracks/cylinder */
int	nsectors = NSECTORS;	/* # sectors/track */
int	nphyssectors;		/* # sectors/track including spares */
int	secpercyl;		/* sectors per cylinder */
int	trackspares = -1;	/* spare sectors per track */
int	cylspares = -1;		/* spare sectors per cylinder */
int	sectorsize;		/* bytes/sector */
int	realsectorsize;		/* bytes/sector in hardware */
int	rpm;			/* revolutions/minute of drive */
int	interleave;		/* hardware sector interleave */
int	trackskew = -1;		/* sector 0 skew, per track */
int	headswitch;		/* head switch time, usec */
int	trackseek;		/* track-to-track seek, usec */
int	fsize = 0;		/* fragment size */
int	bsize = 0;		/* block size */
int	cpg = DESCPG;		/* cylinders/cylinder group */
int	cpgflg;			/* cylinders/cylinder group flag was given */
int	minfree = MINFREE;	/* free space threshold */
int	opt = DEFAULTOPT;	/* optimization preference (space or time) */
int	density;		/* number of bytes per inode */
int	maxcontig = 0;		/* max contiguous blocks to allocate */
int	rotdelay = ROTDELAY;	/* rotational delay between blocks */
int	maxbpg;			/* maximum blocks per file in a cyl group */
int	nrpos = NRPOS;		/* # of distinguished rotational positions */
int	avgfilesize = AVFILESIZ;/* expected average file size */
int	avgfilesperdir = AFPDIR;/* expected number of files per directory */
int	bbsize = BBSIZE;	/* boot block size */
int	sbsize = SBSIZE;	/* superblock size */
int	mntflags = MNT_ASYNC;	/* flags to be passed to mount */
int	t_or_u_flag = 0;	/* user has specified -t or -u */
caddr_t	membase;		/* start address of memory based filesystem */
char	*filename;
u_char	*volumelabel = NULL;	/* volume label for filesystem */
#ifdef COMPAT
char	*disktype;
int	unlabeled;
#endif

char	mfsdevname[256];
char	*progname;

static void usage(void);
static void mfsintr(int signo);

int
main(int argc, char **argv)
{
	int ch, i;
	struct disktab geom;		/* disk geometry data */
	struct stat st;
	struct statfs *mp;
	int fsi = -1, fso = -1, len, n, vflag;
	char *s1, *s2, *special;
	const char *opstring;
#ifdef MFS
	struct vfsconf vfc;
	int error;
#endif

	bzero(&geom, sizeof(geom));
	vflag = 0;
	if ((progname = strrchr(*argv, '/')))
		++progname;
	else
		progname = *argv;

	if (strstr(progname, "mfs")) {
		mfs = 1;
		Nflag++;
	}

	opstring = mfs ?
	    "L:NCF:T:Ua:b:c:d:e:f:g:h:i:m:o:s:v" :
	    "L:NREOS:T:Ua:b:c:d:e:f:g:h:i:k:l:m:n:o:p:r:s:t:u:vx:";
	while ((ch = getopt(argc, argv, opstring)) != -1) {
		switch (ch) {
		case 'E':
			Eflag = 1;
			break;
		case 'L':
			volumelabel = optarg;
			i = -1;
			while (isalnum(volumelabel[++i]))
				;
			if (volumelabel[i] != '\0')
				errx(1, "bad volume label. Valid characters are alphanumerics.");
			if (strlen(volumelabel) >= MAXVOLLEN)
				errx(1, "bad volume label. Length is longer than %d.",
				    MAXVOLLEN);
			Lflag = 1;
			break;
		case 'N':
			Nflag = 1;
			break;
		case 'O':
			Oflag = 1;
			break;
		case 'C':
			Cflag = 1;	/* MFS only */
			break;
		case 'S':
			if ((sectorsize = atoi(optarg)) <= 0)
				fatal("%s: bad sector size", optarg);
			break;
#ifdef COMPAT
		case 'T':
			disktype = optarg;
			break;
#endif
		case 'F':
			filename = optarg;
			break;
		case 'U':
			Uflag = 1;
			break;
		case 'a':
			if ((maxcontig = atoi(optarg)) <= 0)
				fatal("%s: bad maximum contiguous blocks",
				    optarg);
			break;
		case 'b':
			if ((bsize = atoi(optarg)) < MINBSIZE)
				fatal("%s: bad block size", optarg);
			break;
		case 'c':
			if ((cpg = atoi(optarg)) <= 0)
				fatal("%s: bad cylinders/group", optarg);
			cpgflg++;
			break;
		case 'd':
			if ((rotdelay = atoi(optarg)) < 0)
				fatal("%s: bad rotational delay", optarg);
			break;
		case 'e':
			if ((maxbpg = atoi(optarg)) <= 0)
		fatal("%s: bad blocks per file in a cylinder group",
				    optarg);
			break;
		case 'f':
			if ((fsize = atoi(optarg)) <= 0)
				fatal("%s: bad fragment size", optarg);
			break;
		case 'g':
			if ((avgfilesize = atoi(optarg)) <= 0)
				fatal("%s: bad average file size", optarg);
			break;
		case 'h':
			if ((avgfilesperdir = atoi(optarg)) <= 0)
				fatal("%s: bad average files per dir", optarg);
			break;
		case 'i':
			if ((density = atoi(optarg)) <= 0)
				fatal("%s: bad bytes per inode", optarg);
			break;
		case 'k':
			if ((trackskew = atoi(optarg)) < 0)
				fatal("%s: bad track skew", optarg);
			break;
		case 'l':
			if ((interleave = atoi(optarg)) <= 0)
				fatal("%s: bad interleave", optarg);
			break;
		case 'm':
			if ((minfree = atoi(optarg)) < 0 || minfree > 99)
				fatal("%s: bad free space %%", optarg);
			break;
		case 'n':
			if ((nrpos = atoi(optarg)) < 0)
				fatal("%s: bad rotational layout count",
				    optarg);
			if (nrpos == 0)
				nrpos = 1;
			break;
		case 'o':
			if (mfs)
				getmntopts(optarg, mopts, &mntflags, 0);
			else {
				if (strcmp(optarg, "space") == 0)
					opt = FS_OPTSPACE;
				else if (strcmp(optarg, "time") == 0)
					opt = FS_OPTTIME;
				else
	fatal("%s: unknown optimization preference: use `space' or `time'", optarg);
			}
			break;
		case 'p':
			if ((trackspares = atoi(optarg)) < 0)
				fatal("%s: bad spare sectors per track",
				    optarg);
			break;
		case 'r':
			if ((rpm = atoi(optarg)) <= 0)
				fatal("%s: bad revolutions/minute", optarg);
			break;
		case 's':
			/*
			 * Unsigned long but limit to long.  On 32 bit a
			 * tad under 2G, on 64 bit the upper bound is more
			 * swap space then operand size.
			 *
			 * NOTE: fssize is converted from 512 byte sectors
			 * to filesystem block-sized sectors by mkfs XXX.
			 */
			fssize = strtoul(optarg, NULL, 10);
			if (fssize == 0 || fssize > LONG_MAX)
				fatal("%s: bad file system size", optarg);
			break;
		case 't':
			t_or_u_flag++;
			if ((ntracks = atoi(optarg)) < 0)
				fatal("%s: bad total tracks", optarg);
			break;
		case 'u':
			t_or_u_flag++;
			if ((nsectors = atoi(optarg)) < 0)
				fatal("%s: bad sectors/track", optarg);
			break;
		case 'v':
			vflag = 1;
			break;
		case 'x':
			if ((cylspares = atoi(optarg)) < 0)
				fatal("%s: bad spare sectors per cylinder",
				    optarg);
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2 && (mfs || argc != 1))
		usage();

	special = argv[0];
	/* Copy the NetBSD way of faking up a disk label */
        if (mfs && !strcmp(special, "swap")) {
                /* 
                 * it's an MFS, mounted on "swap."  fake up a label.
                 * XXX XXX XXX
                 */
                fso = -1;       /* XXX; normally done below. */

		geom.d_media_blksize = 512;
		geom.d_nheads = 16;
		geom.d_secpertrack = 64;
		/* geom.d_ncylinders not used */
		geom.d_secpercyl = 1024;
		geom.d_media_blocks = 16384;
                geom.d_rpm = 3600;
                geom.d_interleave = 1;

                goto havelabel;
        }

	/*
	 * If we can't stat the device and the path is relative, try
	 * prepending /dev.
	 */
	if (stat(special, &st) < 0 && special[0] && special[0] != '/')
		asprintf(&special, "/dev/%s", special);

	if (Eflag) {
		char sysctl_name[64];
		int trim_enabled = 0;
		size_t olen = sizeof(trim_enabled);
		char *dev_name = strdup(special);

		dev_name = strtok(dev_name + strlen("/dev/da"),"s");
		sprintf(sysctl_name, "kern.cam.da.%s.trim_enabled",
		    dev_name);

		sysctlbyname(sysctl_name, &trim_enabled, &olen, NULL, 0);

		if(errno == ENOENT) {
			printf("Device:%s does not support the TRIM command\n",
			    special);
			usage();
		}
		if(!trim_enabled) {
			printf("Erase device option selected, but sysctl (%s) "
			    "is not enabled\n",sysctl_name);
			usage();
			  
		}
	}
	if (Nflag) {
		fso = -1;
	} else {
		fso = open(special, O_WRONLY);
		if (fso < 0)
			fatal("%s: %s", special, strerror(errno));

		/* Bail if target special is mounted */
		n = getmntinfo(&mp, MNT_NOWAIT);
		if (n == 0)
			fatal("%s: getmntinfo: %s", special, strerror(errno));

		len = sizeof(_PATH_DEV) - 1;
		s1 = special;
		if (strncmp(_PATH_DEV, s1, len) == 0)
			s1 += len;

		while (--n >= 0) {
			s2 = mp->f_mntfromname;
			if (strncmp(_PATH_DEV, s2, len) == 0) {
				s2 += len - 1;
				*s2 = 'r';
			}
			if (strcmp(s1, s2) == 0 || strcmp(s1, &s2[1]) == 0)
				fatal("%s is mounted on %s",
				    special, mp->f_mntonname);
			++mp;
		}
	}
	if (mfs && disktype != NULL) {
		struct disktab *dt;

		if ((dt = getdisktabbyname(disktype)) == NULL)
			fatal("%s: unknown disk type", disktype);
		geom = *dt;
	} else {
		struct partinfo pinfo;

		if (special[0] == 0)
 			fatal("null special file name");
		fsi = open(special, O_RDONLY);
		if (fsi < 0)
			fatal("%s: %s", special, strerror(errno));
		if (fstat(fsi, &st) < 0)
			fatal("%s: %s", special, strerror(errno));
		if ((st.st_mode & S_IFMT) != S_IFCHR && !mfs && !vflag)
			printf("%s: %s: not a character-special device\n",
			    progname, special);
#ifdef COMPAT
		if (!mfs && disktype == NULL)
			disktype = argv[1];
#endif
		if (ioctl(fsi, DIOCGPART, &pinfo) < 0) {
			if (!vflag) {
				fatal("%s: unable to retrieve geometry "
				      "information", argv[0]);
			}
			/*
			 * fake up geometry data
			 */
			geom.d_media_blksize = 512;
			geom.d_nheads = 16;
			geom.d_secpertrack = 64;
			geom.d_secpercyl = 1024;
			geom.d_media_blocks = st.st_size / 
					      geom.d_media_blksize;
			geom.d_media_size = geom.d_media_blocks *
					    geom.d_media_blksize;
			/* geom.d_ncylinders not used */
		} else {
			/*
			 * extract geometry from pinfo
			 */
			geom.d_media_blksize = pinfo.media_blksize;
			geom.d_nheads = pinfo.d_nheads;
			geom.d_secpertrack = pinfo.d_secpertrack;
			geom.d_secpercyl = pinfo.d_secpercyl;
			/* geom.d_ncylinders not used */
			geom.d_media_blocks = pinfo.media_blocks;
			geom.d_media_size = pinfo.media_size;
			slice_offset = pinfo.media_offset;
		}
		if (geom.d_media_blocks == 0 || geom.d_media_size == 0) {
			fatal("%s: is unavailable", argv[0]);
		}
		printf("%s: media size %6.2fMB\n",
		        argv[0], geom.d_media_size / 1024.0 / 1024.0);
		if (geom.d_media_size / 512 >= 0x80000000ULL)
			fatal("%s: media size is too large for newfs to handle",
			      argv[0]);
	}
havelabel:
	if (fssize == 0)
		fssize = geom.d_media_blocks;
	if ((u_long)fssize > geom.d_media_blocks && !mfs) {
	       fatal("%s: maximum file system size is %" PRIu64 " blocks",
		     argv[0], geom.d_media_blocks);
	}
	if (rpm == 0) {
		rpm = geom.d_rpm;
		if (rpm <= 0)
			rpm = 3600;
	}
	if (ntracks == 0) {
		ntracks = geom.d_nheads;
		if (ntracks <= 0)
			fatal("%s: no default #tracks", argv[0]);
	}
	if (nsectors == 0) {
		nsectors = geom.d_secpertrack;
		if (nsectors <= 0)
			fatal("%s: no default #sectors/track", argv[0]);
	}
	if (sectorsize == 0) {
		sectorsize = geom.d_media_blksize;
		if (sectorsize <= 0)
			fatal("%s: no default sector size", argv[0]);
	}
	if (trackskew == -1) {
		trackskew = geom.d_trackskew;
		if (trackskew < 0)
			trackskew = 0;
	}
	if (interleave == 0) {
		interleave = geom.d_interleave;
		if (interleave <= 0)
			interleave = 1;
	}
	if (fsize == 0)
		fsize = MAX(DFL_FRAGSIZE, geom.d_media_blksize);
	if (bsize == 0)
		bsize = MIN(DFL_BLKSIZE, 8 * fsize);
	/*
	 * Maxcontig sets the default for the maximum number of blocks
	 * that may be allocated sequentially. With filesystem clustering
	 * it is possible to allocate contiguous blocks up to the maximum
	 * transfer size permitted by the controller or buffering.
	 */
	if (maxcontig == 0)
		maxcontig = MAX(1, MAXPHYS / bsize - 1);
	if (density == 0)
		density = NFPI * fsize;
	if (minfree < MINFREE && opt != FS_OPTSPACE) {
		fprintf(stderr, "Warning: changing optimization to space ");
		fprintf(stderr, "because minfree is less than %d%%\n", MINFREE);
		opt = FS_OPTSPACE;
	}
	if (trackspares == -1)
		trackspares = 0;
	nphyssectors = nsectors + trackspares;
	if (cylspares == -1)
		cylspares = 0;
	secpercyl = nsectors * ntracks - cylspares;
	/*
	 * Only complain if -t or -u have been specified; the default
	 * case (4096 sectors per cylinder) is intended to disagree
	 * with the disklabel.
	 */
	if (t_or_u_flag && (uint32_t)secpercyl != geom.d_secpercyl)
		fprintf(stderr, "%s (%d) %s (%u)\n",
			"Warning: calculated sectors per cylinder", secpercyl,
			"disagrees with disk label", geom.d_secpercyl);
	if (maxbpg == 0)
		maxbpg = MAXBLKPG(bsize);
	headswitch = geom.d_headswitch;
	trackseek = geom.d_trkseek;
	realsectorsize = sectorsize;
	if (sectorsize != DEV_BSIZE) {		/* XXX */
		int secperblk = sectorsize / DEV_BSIZE;

		sectorsize = DEV_BSIZE;
		nsectors *= secperblk;
		nphyssectors *= secperblk;
		secpercyl *= secperblk;
		fssize *= secperblk;
	}
	if (mfs) {
		mfs_mtpt = argv[1];
		if (
		    stat(mfs_mtpt, &mfs_mtstat) < 0 ||
		    !S_ISDIR(mfs_mtstat.st_mode)
		) {
			fatal("mount point not dir: %s", mfs_mtpt);
		}
	}
	mkfs(special, fsi, fso, (Cflag && mfs) ? argv[1] : NULL);

	/*
	 * NOTE: Newfs no longer accesses or attempts to update the
	 * filesystem disklabel.
	 *
	 * NOTE: fssize is converted from 512 byte sectors
	 * to filesystem block-sized sectors by mkfs XXX.
	 */
	if (!Nflag)
		close(fso);
	close(fsi);
#ifdef MFS
	if (mfs) {
		struct mfs_args args;

		bzero(&args, sizeof(args));

		snprintf(mfsdevname, sizeof(mfsdevname), "/dev/mfs%d",
			getpid());
		args.fspec = mfsdevname;
		args.export.ex_root = -2;
		if (mntflags & MNT_RDONLY)
			args.export.ex_flags = MNT_EXRDONLY;
		else
			args.export.ex_flags = 0;
		args.base = membase;
		args.size = fssize * fsize;

		error = getvfsbyname("mfs", &vfc);
		if (error && vfsisloadable("mfs")) {
			if (vfsload("mfs"))
				fatal("vfsload(mfs)");
			endvfsent();	/* flush cache */
			error = getvfsbyname("mfs", &vfc);
		}
		if (error)
			fatal("mfs filesystem not available");

#if 0
		int udev;
		udev = (253 << 8) | (getpid() & 255) | 
			((getpid() & ~0xFF) << 8);
		if (mknod(mfsdevname, S_IFCHR | 0700, udev) < 0)
			printf("Warning: unable to create %s\n", mfsdevname);
#endif
		signal(SIGINT, mfsintr);
		if (mount(vfc.vfc_name, argv[1], mntflags, &args) < 0)
			fatal("%s: %s", argv[1], strerror(errno));
		signal(SIGINT, SIG_DFL);
		mfsintr(SIGINT);
	}
#endif
	exit(0);
}

#ifdef MFS

static void
mfsintr(__unused int signo)
{
	if (filename)
		munmap(membase, fssize * fsize);
#if 0
	remove(mfsdevname);
#endif
}

#endif

/*VARARGS*/
void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (fcntl(STDERR_FILENO, F_GETFL) < 0) {
		openlog(progname, LOG_CONS, LOG_DAEMON);
		vsyslog(LOG_ERR, fmt, ap);
		closelog();
	} else {
		vwarnx(fmt, ap);
	}
	va_end(ap);
	exit(1);
	/*NOTREACHED*/
}

void
usage(void)
{
	if (mfs) {
		fprintf(stderr,
		    "usage: %s [ -fsoptions ] special-device mount-point\n",
			progname);
	} else
		fprintf(stderr,
		    "usage: %s [ -fsoptions ] special-device%s\n",
		    progname,
#ifdef COMPAT
		    " [device-type]");
#else
		    "");
#endif
	fprintf(stderr, "where fsoptions are:\n");
	fprintf(stderr, "\t-C (mfs) Copy the underlying filesystem to the MFS mount\n");
	fprintf(stderr, "\t-E erase file system contents using TRIM\n");
	fprintf(stderr, "\t-L volume name\n");
	fprintf(stderr,
	    "\t-N do not create file system, just print out parameters\n");
	fprintf(stderr, "\t-O create a 4.3BSD format filesystem\n");
	fprintf(stderr, "\t-R enable TRIM\n");
	fprintf(stderr, "\t-S sector size\n");
#ifdef COMPAT
	fprintf(stderr, "\t-T disktype\n");
#endif
	fprintf(stderr, "\t-U enable soft updates\n");
	fprintf(stderr, "\t-a maximum contiguous blocks\n");
	fprintf(stderr, "\t-b block size\n");
	fprintf(stderr, "\t-c cylinders/group\n");
	fprintf(stderr, "\t-d rotational delay between contiguous blocks\n");
	fprintf(stderr, "\t-e maximum blocks per file in a cylinder group\n");
	fprintf(stderr, "\t-f frag size\n");
	fprintf(stderr, "\t-g average file size\n");
	fprintf(stderr, "\t-h average files per directory\n");
	fprintf(stderr, "\t-i number of bytes per inode\n");
	fprintf(stderr, "\t-k sector 0 skew, per track\n");
	fprintf(stderr, "\t-l hardware sector interleave\n");
	fprintf(stderr, "\t-m minimum free space %%\n");
	fprintf(stderr, "\t-n number of distinguished rotational positions\n");
	fprintf(stderr, "\t-o optimization preference (`space' or `time')\n");
	fprintf(stderr, "\t-p spare sectors per track\n");
	fprintf(stderr, "\t-s file system size (sectors)\n");
	fprintf(stderr, "\t-r revolutions/minute\n");
	fprintf(stderr, "\t-t tracks/cylinder\n");
	fprintf(stderr, "\t-u sectors/track\n");
	fprintf(stderr,
        "\t-v do not attempt to determine partition name from device name\n");
	fprintf(stderr, "\t-x spare sectors per cylinder\n");
	exit(1);
}
