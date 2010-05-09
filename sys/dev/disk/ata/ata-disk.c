/*-
 * Copyright (c) 1998,1999,2000,2001,2002 S�ren Schmidt <sos@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/ata/ata-disk.c,v 1.60.2.24 2003/01/30 07:19:59 sos Exp $
 * $DragonFly: src/sys/dev/disk/ata/ata-disk.c,v 1.36 2007/05/19 02:39:02 dillon Exp $
 */

#include "opt_ata.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ata.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/disk.h>
#include <sys/devicestat.h>
#include <sys/cons.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/rman.h>
#include <sys/proc.h>
#include <sys/buf2.h>
#include <sys/thread2.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/md_var.h>
#include <machine/clock.h>

#include "ata-all.h"
#include "ata-disk.h"
#include "ata-raid.h"

/* device structures */
static d_open_t		adopen;
static d_close_t	adclose;
static d_strategy_t	adstrategy;
static d_dump_t		addump;

static struct dev_ops ad_ops = {
	{ "ad", 116, D_DISK },
	.d_open =	adopen,
	.d_close =	adclose,
	.d_read =	physread,
	.d_write =	physwrite,
	.d_strategy =	adstrategy,
	.d_dump =	addump,
};

/* prototypes */
static void ad_requeue(struct ata_channel *, struct ad_request *);
static void ad_invalidatequeue(struct ad_softc *, struct ad_request *);
static int ad_tagsupported(struct ad_softc *);
static void ad_timeout(struct ad_request *);
static void ad_free(struct ad_request *);
static int ad_version(u_int16_t);

/* misc defines */
#define AD_MAX_RETRIES	3

/* internal vars */
static u_int32_t adp_lun_map = 0;
static int ata_dma = 1;
static int ata_wc = 1;
static int ata_tags = 0; 
TUNABLE_INT("hw.ata.ata_dma", &ata_dma);
TUNABLE_INT("hw.ata.wc", &ata_wc);
TUNABLE_INT("hw.ata.tags", &ata_tags);
static MALLOC_DEFINE(M_AD, "AD driver", "ATA disk driver");

/* sysctl vars */
SYSCTL_DECL(_hw_ata);
SYSCTL_INT(_hw_ata, OID_AUTO, ata_dma, CTLFLAG_RD, &ata_dma, 0,
	   "ATA disk DMA mode control");
SYSCTL_INT(_hw_ata, OID_AUTO, wc, CTLFLAG_RD, &ata_wc, 0,
	   "ATA disk write caching");
SYSCTL_INT(_hw_ata, OID_AUTO, tags, CTLFLAG_RD, &ata_tags, 0,
	   "ATA disk tagged queuing support");

void
ad_attach(struct ata_device *atadev, int alreadylocked)
{
    struct ad_softc *adp;
    struct disk_info info;
    cdev_t dev;

    adp = kmalloc(sizeof(struct ad_softc), M_AD, M_WAITOK | M_ZERO);

    KKASSERT(atadev->channel->req_mpipe.max_count != 0);

    adp->device = atadev;
#ifdef ATA_STATIC_ID
    adp->lun = (device_get_unit(atadev->channel->dev)<<1)+ATA_DEV(atadev->unit);
#else
    adp->lun = ata_get_lun(&adp_lun_map);
#endif
    ata_set_name(atadev, "ad", adp->lun);
    adp->heads = atadev->param->heads;
    adp->sectors = atadev->param->sectors;
    adp->total_secs = atadev->param->cylinders * adp->heads * adp->sectors;	
    bioq_init(&adp->bio_queue);

    /* does this device need oldstyle CHS addressing */
    if (!ad_version(atadev->param->version_major) || 
	!(atadev->param->atavalid & ATA_FLAG_54_58) || !atadev->param->lba_size)
	adp->flags |= AD_F_CHS_USED;

    /* use the 28bit LBA size if valid */
    if (atadev->param->cylinders == 16383 &&
	adp->total_secs < atadev->param->lba_size)
	adp->total_secs = atadev->param->lba_size;

    /* use the 48bit LBA size if valid */
    if (atadev->param->support.address48 &&
	atadev->param->lba_size48 > 268435455)
	adp->total_secs = atadev->param->lba_size48;
    
    if (!alreadylocked)
	ATA_SLEEPLOCK_CH(atadev->channel, ATA_CONTROL);
    /* use multiple sectors/interrupt if device supports it */
    adp->transfersize = DEV_BSIZE;
    if (ad_version(atadev->param->version_major)) {
	int secsperint = max(1, min(atadev->param->sectors_intr, 16));

	if (!ata_command(atadev, ATA_C_SET_MULTI, 0, secsperint,
			 0, ATA_WAIT_INTR) && !ata_wait(atadev, 0))
	adp->transfersize *= secsperint;
    }

    /* enable read caching if not default on device */
    if (ata_command(atadev, ATA_C_SETFEATURES,
		    0, 0, ATA_C_F_ENAB_RCACHE, ATA_WAIT_INTR))
	ata_prtdev(atadev, "enabling readahead cache failed\n");

    /* enable write caching if allowed and not default on device */
    if (ata_wc || (ata_tags && ad_tagsupported(adp))) {
	if (ata_command(atadev, ATA_C_SETFEATURES,
			0, 0, ATA_C_F_ENAB_WCACHE, ATA_WAIT_INTR))
	    ata_prtdev(atadev, "enabling write cache failed\n");
    }
    else {
	if (ata_command(atadev, ATA_C_SETFEATURES,
			0, 0, ATA_C_F_DIS_WCACHE, ATA_WAIT_INTR))
	    ata_prtdev(atadev, "disabling write cache failed\n");
    }

    /* use DMA if allowed and if drive/controller supports it */
    if (ata_dma)
	ata_dmainit(atadev, ata_pmode(atadev->param), 
		    ata_wmode(atadev->param), ata_umode(atadev->param));
    else
	ata_dmainit(atadev, ata_pmode(atadev->param), -1, -1);

    /* use tagged queueing if allowed and supported */
    if (ata_tags && ad_tagsupported(adp)) {
	adp->num_tags = atadev->param->queuelen;
	adp->flags |= AD_F_TAG_ENABLED;
	adp->device->channel->flags |= ATA_QUEUED;
	if (ata_command(atadev, ATA_C_SETFEATURES,
			0, 0, ATA_C_F_DIS_RELIRQ, ATA_WAIT_INTR))
	    ata_prtdev(atadev, "disabling release interrupt failed\n");
	if (ata_command(atadev, ATA_C_SETFEATURES,
			0, 0, ATA_C_F_DIS_SRVIRQ, ATA_WAIT_INTR))
	    ata_prtdev(atadev, "disabling service interrupt failed\n");
    }

    ATA_UNLOCK_CH(atadev->channel);

    devstat_add_entry(&adp->stats, "ad", adp->lun, DEV_BSIZE,
		      DEVSTAT_NO_ORDERED_TAGS,
		      DEVSTAT_TYPE_DIRECT | DEVSTAT_TYPE_IF_IDE,
		      DEVSTAT_PRIORITY_DISK);

    dev = disk_create(adp->lun, &adp->disk, &ad_ops);
    dev->si_drv1 = adp;
    dev->si_iosize_max = 256 * DEV_BSIZE;
    adp->dev = dev;

    /* construct the disk_info */
    bzero(&info, sizeof(info));
    info.d_media_blksize = DEV_BSIZE;
    info.d_media_blocks = adp->total_secs;
    info.d_nheads = adp->heads;
    info.d_secpertrack = adp->sectors;
    info.d_ncylinders = adp->total_secs / 
			 (info.d_nheads * info.d_secpertrack);
    info.d_secpercyl = info.d_secpertrack * info.d_nheads;
    disk_setdiskinfo(&adp->disk, &info);

    atadev->driver = adp;
    atadev->flags = 0;

    /* if this disk belongs to an ATA RAID dont print the probe */
    if (ata_raiddisk_attach(adp))
	adp->flags |= AD_F_RAID_SUBDISK;
    else {
	if (atadev->driver) {
	    ad_print(adp);
	    ata_enclosure_print(atadev);
	}
    }
}

void
ad_detach(struct ata_device *atadev, int flush) /* get rid of flush XXX SOS */
{
    struct ad_softc *adp = atadev->driver;
    struct ad_request *request;
    struct bio *bio;
    struct buf *bp;

    atadev->flags |= ATA_D_DETACHING;
    ata_prtdev(atadev, "removed from configuration\n");
    ad_invalidatequeue(adp, NULL);
    TAILQ_FOREACH(request, &atadev->channel->ata_queue, chain) {
	if (request->softc != adp)
	    continue;
	TAILQ_REMOVE(&atadev->channel->ata_queue, request, chain);
	request->bio->bio_buf->b_error = ENXIO;
	request->bio->bio_buf->b_flags |= B_ERROR;
	biodone(request->bio);
	ad_free(request);
    }
    ata_dmafree(atadev);
    while ((bio = bioq_first(&adp->bio_queue))) {
	bioq_remove(&adp->bio_queue, bio); 
	bp = bio->bio_buf;
	bp->b_error = ENXIO;
	bp->b_flags |= B_ERROR;
	biodone(bio);
    }
    disk_invalidate(&adp->disk);
    devstat_remove_entry(&adp->stats);
    disk_destroy(&adp->disk);
    if (flush) {
	if (ata_command(atadev, ATA_C_FLUSHCACHE, 0, 0, 0, ATA_WAIT_READY))
	    ata_prtdev(atadev, "flushing cache on detach failed\n");
    }
    if (adp->flags & AD_F_RAID_SUBDISK)
	ata_raiddisk_detach(adp);
    ata_free_name(atadev);
    ata_free_lun(&adp_lun_map, adp->lun);
    atadev->driver = NULL;
    atadev->flags = 0;
    kfree(adp, M_AD);
}

static int
adopen(struct dev_open_args *ap)
{
    struct ad_softc *adp = ap->a_head.a_dev->si_drv1;

    if (adp->flags & AD_F_RAID_SUBDISK)
	return EBUSY;
    return 0;
}

static int
adclose(struct dev_close_args *ap)
{
    struct ad_softc *adp = ap->a_head.a_dev->si_drv1;

    crit_enter();	/* interlock non-atomic channel lock */
    ATA_SLEEPLOCK_CH(adp->device->channel, ATA_CONTROL);
    if (ata_command(adp->device, ATA_C_FLUSHCACHE, 0, 0, 0, ATA_WAIT_READY))
	ata_prtdev(adp->device, "flushing cache on close failed\n");
    ATA_UNLOCK_CH(adp->device->channel);
    crit_exit();
    return 0;
}

/*
 * note: always use the passed device rather then bp->b_dev, as the bp
 * may have been translated through several layers.
 */
static int 
adstrategy(struct dev_strategy_args *ap)
{
    cdev_t dev = ap->a_head.a_dev;
    struct bio *bio = ap->a_bio;
    struct buf *bp = bio->bio_buf;
    struct ad_softc *adp = dev->si_drv1;

    if (adp->device->flags & ATA_D_DETACHING) {
	bp->b_error = ENXIO;
	bp->b_flags |= B_ERROR;
	biodone(bio);
	return(0);
    }
    bio->bio_driver_info = dev;
    crit_enter();
    bioqdisksort(&adp->bio_queue, bio);
    crit_exit();
    ata_start(adp->device->channel);
    return(0);
}

int
addump(struct dev_dump_args *ap)
{
    cdev_t dev = ap->a_head.a_dev;
    struct ad_softc *adp = dev->si_drv1;
    struct ad_request request;

    if (!adp)
	return ENXIO;

    /* force PIO mode for dumps */
    adp->device->mode = ATA_PIO;
    ata_reinit(adp->device->channel);

    /* set up request */
    bzero(&request, sizeof(struct ad_request));
    request.softc = adp;
    request.blockaddr = ap->a_offset / DEV_BSIZE;
    request.bytecount = ap->a_length;
    request.data = ap->a_virtual;
    callout_init(&request.callout);
    while (request.bytecount > 0) {
        ad_transfer(&request);
        if (request.flags & ADR_F_ERROR)
    	    return EIO;
        request.donecount += request.currentsize;
        request.bytecount -= request.currentsize;
        DELAY(20);
    }

    if (ata_wait(adp->device, ATA_S_READY | ATA_S_DSC) < 0)
	ata_prtdev(adp->device, "timeout waiting for final ready\n");

    return 0;
}

/*
 * Critical section is held when this function is called
 * by ata_start().
 */
void
ad_start(struct ata_device *atadev)
{
    struct ad_softc *adp = atadev->driver;
    struct bio *bio = bioq_first(&adp->bio_queue);
    struct buf *bp;
    struct ad_request *request;
    int tag = 0;

    if (bio == NULL)
	return;
    bp = bio->bio_buf;

    /* if tagged queueing enabled get next free tag */
    if (adp->flags & AD_F_TAG_ENABLED) {
	while (tag <= adp->num_tags && adp->tags[tag])
	    tag++;
	if (tag > adp->num_tags )
	    return;
    }

    /*
     * Allocate a request.  The allocation can only fail if the pipeline
     * is full, in which case the request will be picked up later when
     * ad_start() is called after another request completes.
     */
    request = mpipe_alloc_nowait(&atadev->channel->req_mpipe);
    if (request == NULL) {
	ata_prtdev(atadev, "pipeline full allocating request in ad_start\n");
	return;
    }

    KASSERT((bio->bio_offset & DEV_BMASK) == 0,
	    ("bio_offset not on sector boundary %08llx", bio->bio_offset));

    /* setup request */
    request->softc = adp;
    request->bio = bio;
    request->blockaddr = (u_int64_t)(bio->bio_offset >> DEV_BSHIFT);
    request->bytecount = bp->b_bcount;
    request->data = bp->b_data;
    request->tag = tag;
    callout_init(&request->callout);
    if (bp->b_cmd == BUF_CMD_READ)
	request->flags |= ADR_F_READ;
    if (adp->device->mode >= ATA_DMA) {
	if (ata_dmaalloc(atadev, M_NOWAIT) != 0) {
	    mpipe_free(&atadev->channel->req_mpipe, request);
	    ata_prtdev(atadev, "pipeline full allocated dmabuf in ad_start\n");
	    /* do not revert to PIO, wait for ad_start after I/O completion */
	    return;
	}
    }

    /* insert in tag array */
    adp->tags[tag] = request;

    /* remove from drive queue */
    bioq_remove(&adp->bio_queue, bio); 

    /* link onto controller queue */
    TAILQ_INSERT_TAIL(&atadev->channel->ata_queue, request, chain);
}

void
ad_requeue(struct ata_channel *chan, struct ad_request *req)
{
        if (req->donecount) {
                ata_printf(chan, -1,
			"WARNING: resetting donecount %u for retry\n",
			 req->donecount);
                req->bytecount += req->donecount;
                req->donecount = 0;
        }
        TAILQ_INSERT_HEAD(&chan->ata_queue, req, chain);
}

int
ad_transfer(struct ad_request *request)
{
    struct ad_softc *adp;
    u_int64_t lba;
    u_int32_t count, max_count;
    u_int8_t cmd;
    int flags = ATA_IMMEDIATE;

    /* get request params */
    adp = request->softc;

    /* calculate transfer details */
    lba = request->blockaddr + (request->donecount / DEV_BSIZE);
   
    if (request->donecount == 0) {

	/* start timeout for this transfer */
	if (dumping) {
		callout_stop(&request->callout);
	} else {
		callout_reset(&request->callout, 10 * hz, 
				(void *)ad_timeout, request);
	}

	/* setup transfer parameters */
	count = howmany(request->bytecount, DEV_BSIZE);
	max_count = adp->device->param->support.address48 ? 65536 : 256;
	if (count > max_count) {
	    ata_prtdev(adp->device,
		       "count %d size transfers not supported\n", count);
	    count = max_count;
	}

	if (adp->flags & AD_F_CHS_USED) {
	    int sector = (lba % adp->sectors) + 1;
	    int cylinder = lba / (adp->sectors * adp->heads);
	    int head = (lba % (adp->sectors * adp->heads)) / adp->sectors;

	    lba = (sector&0xff) | ((cylinder&0xffff)<<8) | ((head&0xf)<<24);
	    adp->device->flags |= ATA_D_USE_CHS;
	}

	/* setup first transfer length */
	request->currentsize = min(request->bytecount, adp->transfersize);

	devstat_start_transaction(&adp->stats);

	/* does this drive & transfer work with DMA ? */
	request->flags &= ~ADR_F_DMA_USED;
	if (adp->device->mode >= ATA_DMA &&
	    !ata_dmasetup(adp->device, request->data, request->bytecount)) {
	    request->flags |= ADR_F_DMA_USED;
	    request->currentsize = request->bytecount;

	    /* do we have tags enabled ? */
	    if (adp->flags & AD_F_TAG_ENABLED) {
		cmd = (request->flags & ADR_F_READ) ?
		    ATA_C_READ_DMA_QUEUED : ATA_C_WRITE_DMA_QUEUED;

		if (ata_command(adp->device, cmd, lba,
				request->tag << 3, count, flags)) {
		    ata_prtdev(adp->device, "error executing command");
		    goto transfer_failed;
		}
		if (ata_wait(adp->device, ATA_S_READY)) {
		    ata_prtdev(adp->device, "timeout waiting for READY\n");
		    goto transfer_failed;
		}
		adp->outstanding++;

		/* if ATA bus RELEASE check for SERVICE */
		if (adp->flags & AD_F_TAG_ENABLED &&
		    ATA_INB(adp->device->channel->r_io, ATA_IREASON) &
		    ATA_I_RELEASE)
		    return ad_service(adp, 1);
	    }
	    else {
		cmd = (request->flags & ADR_F_READ) ?
		    ATA_C_READ_DMA : ATA_C_WRITE_DMA;

		if (ata_command(adp->device, cmd, lba, count, 0, flags)) {
		    ata_prtdev(adp->device, "error executing command");
		    goto transfer_failed;
		}
#if 0
		/*
		 * wait for data transfer phase
		 *
		 * well this should be here acording to specs, but older
		 * promise controllers doesn't like it, they lockup!
		 */
		if (ata_wait(adp->device, ATA_S_READY | ATA_S_DRQ)) {
		    ata_prtdev(adp->device, "timeout waiting for data phase\n");
		    goto transfer_failed;
		}
#endif
	    }

	    /* start transfer, return and wait for interrupt */
	    ata_dmastart(adp->device, request->data, request->bytecount,
			request->flags & ADR_F_READ);
	    return ATA_OP_CONTINUES;
	}

	/* does this drive support multi sector transfers ? */
	if (request->currentsize > DEV_BSIZE)
	    cmd = request->flags&ADR_F_READ ? ATA_C_READ_MUL : ATA_C_WRITE_MUL;

	/* just plain old single sector transfer */
	else
	    cmd = request->flags&ADR_F_READ ? ATA_C_READ : ATA_C_WRITE;

	if (ata_command(adp->device, cmd, lba, count, 0, flags)){
	    ata_prtdev(adp->device, "error executing command");
	    goto transfer_failed;
	}
    }
   
    /* calculate this transfer length */
    request->currentsize = min(request->bytecount, adp->transfersize);

    /* if this is a PIO read operation, return and wait for interrupt */
    if (request->flags & ADR_F_READ)
	return ATA_OP_CONTINUES;

    /* ready to write PIO data ? */
    if (ata_wait(adp->device, (ATA_S_READY | ATA_S_DSC | ATA_S_DRQ)) < 0) {
	ata_prtdev(adp->device, "timeout waiting for DRQ");
	goto transfer_failed;
    }

    /* output the data */
    if (adp->device->channel->flags & ATA_USE_16BIT)
	ATA_OUTSW(adp->device->channel->r_io, ATA_DATA,
		  (void *)((uintptr_t)request->data + request->donecount),
		  request->currentsize / sizeof(int16_t));
    else
	ATA_OUTSL(adp->device->channel->r_io, ATA_DATA,
		  (void *)((uintptr_t)request->data + request->donecount),
		  request->currentsize / sizeof(int32_t));
    return ATA_OP_CONTINUES;

transfer_failed:
    callout_stop(&request->callout);
    ad_invalidatequeue(adp, request);
    kprintf(" - resetting\n");

    /* if retries still permit, reinject this request */
    if (request->retries++ < AD_MAX_RETRIES)
	ad_requeue(adp->device->channel, request);
    else {
	/* retries all used up, return error */
	request->bio->bio_buf->b_error = EIO;
	request->bio->bio_buf->b_flags |= B_ERROR;
	request->bio->bio_buf->b_resid = request->bytecount;
	devstat_end_transaction_buf(&adp->stats, request->bio->bio_buf);
	biodone(request->bio);
	ad_free(request);
    }
    ata_reinit(adp->device->channel);
    return ATA_OP_CONTINUES;
}

int
ad_interrupt(struct ad_request *request)
{
    struct ad_softc *adp = request->softc;
    int dma_stat = 0;
    cdev_t dev;

    /* finish DMA transfer */
    if (request->flags & ADR_F_DMA_USED)
	dma_stat = ata_dmadone(adp->device);

    dev = request->bio->bio_driver_info;
    /* do we have a corrected soft error ? */
    if (adp->device->channel->status & ATA_S_CORR)
	diskerr(request->bio, dev,
		"soft error (ECC corrected)", LOG_PRINTF,
		request->donecount);

    /* did any real errors happen ? */
    if ((adp->device->channel->status & ATA_S_ERROR) ||
	(request->flags & ADR_F_DMA_USED && dma_stat & ATA_BMSTAT_ERROR)) {
	adp->device->channel->error =
	    ATA_INB(adp->device->channel->r_io, ATA_ERROR);
	diskerr(request->bio, dev,
		(adp->device->channel->error & ATA_E_ICRC) ?
		"UDMA ICRC error" : "hard error", LOG_PRINTF,
		request->donecount);

	/* if this is a UDMA CRC error, reinject request */
	if (request->flags & ADR_F_DMA_USED &&
	    adp->device->channel->error & ATA_E_ICRC) {
	    callout_stop(&request->callout);
	    ad_invalidatequeue(adp, request);

	    if (request->retries++ < AD_MAX_RETRIES)
		kprintf(" retrying\n");
	    else {
		ata_dmainit(adp->device, ata_pmode(adp->device->param), -1, -1);
		kprintf(" falling back to PIO mode\n");
	    }
	    ad_requeue(adp->device->channel, request);
	    return ATA_OP_FINISHED;
	}

	/* if using DMA, try once again in PIO mode */
	if (request->flags & ADR_F_DMA_USED) {
	    callout_stop(&request->callout);
	    ad_invalidatequeue(adp, request);
	    ata_dmainit(adp->device, ata_pmode(adp->device->param), -1, -1);
	    request->flags |= ADR_F_FORCE_PIO;
	    kprintf(" trying PIO mode\n");
	    ad_requeue(adp->device->channel, request);
	    return ATA_OP_FINISHED;
	}

	request->flags |= ADR_F_ERROR;
	kprintf(" status=%02x error=%02x\n", 
	       adp->device->channel->status, adp->device->channel->error);
    }

    /* if we arrived here with forced PIO mode, DMA doesn't work right */
    if (request->flags & ADR_F_FORCE_PIO && !(request->flags & ADR_F_ERROR))
	ata_prtdev(adp->device, "DMA problem fallback to PIO mode\n");

    /* if this was a PIO read operation, get the data */
    if (!(request->flags & ADR_F_DMA_USED) &&
	(request->flags & (ADR_F_READ | ADR_F_ERROR)) == ADR_F_READ) {

	/* ready to receive data? */
	if ((adp->device->channel->status & ATA_S_READY) == 0)
	    ata_prtdev(adp->device, "read interrupt arrived early");

	if (ata_wait(adp->device, (ATA_S_READY | ATA_S_DSC | ATA_S_DRQ)) != 0) {
	    ata_prtdev(adp->device, "read error detected (too) late");
	    request->flags |= ADR_F_ERROR;
	}
	else {
	    /* data ready, read in */
	    if (adp->device->channel->flags & ATA_USE_16BIT)
		ATA_INSW(adp->device->channel->r_io, ATA_DATA,
			 (void*)((uintptr_t)request->data + request->donecount),
			 request->currentsize / sizeof(int16_t));
	    else
		ATA_INSL(adp->device->channel->r_io, ATA_DATA,
			 (void*)((uintptr_t)request->data + request->donecount),
			 request->currentsize / sizeof(int32_t));
	}
    }

    /* finish up transfer */
    if (request->flags & ADR_F_ERROR) {
	request->bio->bio_buf->b_error = EIO;
	request->bio->bio_buf->b_flags |= B_ERROR;
    } 
    else {
	request->bytecount -= request->currentsize;
	request->donecount += request->currentsize;
	if (request->bytecount > 0) {
	    ad_transfer(request);
	    return ATA_OP_CONTINUES;
	}
    }

    /* disarm timeout for this transfer */
    callout_stop(&request->callout);

    request->bio->bio_buf->b_resid = request->bytecount;

    devstat_end_transaction_buf(&adp->stats, request->bio->bio_buf);
    biodone(request->bio);
    ad_free(request);
    adp->outstanding--;

    /* check for SERVICE (tagged operations only) */
    return ad_service(adp, 1);
}

int
ad_service(struct ad_softc *adp, int change)
{
    /* do we have to check the other device on this channel ? */
    if (adp->device->channel->flags & ATA_QUEUED && change) {
	int device = adp->device->unit;

	if (adp->device->unit == ATA_MASTER) {
	    if ((adp->device->channel->devices & ATA_ATA_SLAVE) &&
		(adp->device->channel->device[SLAVE].driver) &&
		((struct ad_softc *) (adp->device->channel->
		 device[SLAVE].driver))->flags & AD_F_TAG_ENABLED)
		device = ATA_SLAVE;
	}
	else {
	    if ((adp->device->channel->devices & ATA_ATA_MASTER) &&
		(adp->device->channel->device[MASTER].driver) &&
		((struct ad_softc *) (adp->device->channel->
		 device[MASTER].driver))->flags & AD_F_TAG_ENABLED)
		device = ATA_MASTER;
	}
	if (device != adp->device->unit &&
	    ((struct ad_softc *)
	     (adp->device->channel->
	      device[ATA_DEV(device)].driver))->outstanding > 0) {
	    ATA_OUTB(adp->device->channel->r_io, ATA_DRIVE, ATA_D_IBM | device);
	    adp = adp->device->channel->device[ATA_DEV(device)].driver;
	    DELAY(10);
	}
    }
    adp->device->channel->status =
	ATA_INB(adp->device->channel->r_altio, ATA_ALTSTAT);
 
    /* do we have a SERVICE request from the drive ? */
    if (adp->flags & AD_F_TAG_ENABLED &&
	adp->outstanding > 0 &&
	adp->device->channel->status & ATA_S_SERVICE) {
	struct ad_request *request;
	int tag;

	/* check for error */
	if (adp->device->channel->status & ATA_S_ERROR) {
	    ata_prtdev(adp->device, "Oops! controller says s=0x%02x e=0x%02x\n",
		       adp->device->channel->status,
		       adp->device->channel->error);
	    ad_invalidatequeue(adp, NULL);
	    return ATA_OP_FINISHED;
	}

	/* issue SERVICE cmd */
	if (ata_command(adp->device, ATA_C_SERVICE, 0, 0, 0, ATA_IMMEDIATE)) {
	    ata_prtdev(adp->device, "problem executing SERVICE cmd\n");
	    ad_invalidatequeue(adp, NULL);
	    return ATA_OP_FINISHED;
	}

	/* setup the transfer environment when ready */
	if (ata_wait(adp->device, ATA_S_READY)) {
	    ata_prtdev(adp->device, "SERVICE timeout tag=%d s=%02x e=%02x\n",
		       ATA_INB(adp->device->channel->r_io, ATA_COUNT) >> 3,
		       adp->device->channel->status,
		       adp->device->channel->error);
	    ad_invalidatequeue(adp, NULL);
	    return ATA_OP_FINISHED;
	}
	tag = ATA_INB(adp->device->channel->r_io, ATA_COUNT) >> 3;
	if (!(request = adp->tags[tag])) {
	    ata_prtdev(adp->device, "no request for tag=%d\n", tag);	
	    ad_invalidatequeue(adp, NULL);
	    return ATA_OP_FINISHED;
	}
	ATA_FORCELOCK_CH(adp->device->channel, ATA_ACTIVE_ATA);
	adp->device->channel->running = request;
	request->serv++;

	/* start DMA transfer when ready */
	if (ata_wait(adp->device, ATA_S_READY | ATA_S_DRQ)) {
	    ata_prtdev(adp->device, "timeout starting DMA s=%02x e=%02x\n",
		       adp->device->channel->status,
		       adp->device->channel->error);
	    ad_invalidatequeue(adp, NULL);
	    return ATA_OP_FINISHED;
	}
	ata_dmastart(adp->device, request->data, request->bytecount,
		    request->flags & ADR_F_READ);
	return ATA_OP_CONTINUES;
    }
    return ATA_OP_FINISHED;
}

static void
ad_free(struct ad_request *request)
{
    crit_enter();
    ata_dmafree(request->softc->device);
    request->softc->tags[request->tag] = NULL;
    mpipe_free(&request->softc->device->channel->req_mpipe, request);
    crit_exit();
}

static void
ad_invalidatequeue(struct ad_softc *adp, struct ad_request *request)
{
    /* if tags used invalidate all other tagged transfers */
    if (adp->flags & AD_F_TAG_ENABLED) {
	struct ad_request *tmpreq;
	int tag;

	ata_prtdev(adp->device, "invalidating queued requests\n");
	for (tag = 0; tag <= adp->num_tags; tag++) {
	    tmpreq = adp->tags[tag];
	    adp->tags[tag] = NULL;
	    if (tmpreq == request || tmpreq == NULL)
		continue;
	    callout_stop(&request->callout);
	    ad_requeue(adp->device->channel, tmpreq);
	}
	if (ata_command(adp->device, ATA_C_NOP,
			0, 0, ATA_C_F_FLUSHQUEUE, ATA_WAIT_READY))
	    ata_prtdev(adp->device, "flush queue failed\n");
	adp->outstanding = 0;
    }
}

static int
ad_tagsupported(struct ad_softc *adp)
{
    const char *good[] = {"IBM-DPTA", "IBM-DTLA", NULL};
    int i = 0;

    switch (adp->device->channel->chiptype) {
    case 0x4d33105a: /* Promises before TX2 doesn't work with tagged queuing */
    case 0x4d38105a:
    case 0x0d30105a:
    case 0x4d30105a:  
	return 0;
    }

    /* check that drive does DMA, has tags enabled, and is one we know works */
    if (adp->device->mode >= ATA_DMA && adp->device->param->support.queued && 
	adp->device->param->enabled.queued) {
	while (good[i] != NULL) {
	    if (!strncmp(adp->device->param->model, good[i], strlen(good[i])))
		return 1;
	    i++;
	}
	/* 
	 * check IBM's new obscure way of naming drives 
	 * we want "IC" (IBM CORP) and "AT" or "AV" (ATA interface)
	 * but doesn't care about the other info (size, capacity etc)
	 */
	if (!strncmp(adp->device->param->model, "IC", 2) &&
	    (!strncmp(adp->device->param->model + 8, "AT", 2) ||
	     !strncmp(adp->device->param->model + 8, "AV", 2)))
		return 1;
    }
    return 0;
}

static void
ad_timeout(struct ad_request *request)
{
    struct ad_softc *adp = request->softc;

    adp->device->channel->running = NULL;
    ata_prtdev(adp->device, "%s command timeout tag=%d serv=%d - resetting\n",
	       (request->flags & ADR_F_READ) ? "READ" : "WRITE",
	       request->tag, request->serv);

    if (request->flags & ADR_F_DMA_USED) {
	ata_dmadone(adp->device);
	ad_invalidatequeue(adp, request);
	if (request->retries == AD_MAX_RETRIES) {
	    ata_dmainit(adp->device, ata_pmode(adp->device->param), -1, -1);
	    ata_prtdev(adp->device, "trying fallback to PIO mode\n");
	    request->retries = 0;
	}
    }

    /* if retries still permit, reinject this request */
    if (request->retries++ < AD_MAX_RETRIES) {
	ad_requeue(adp->device->channel, request);
    }
    else {
	/* retries all used up, return error */
	request->bio->bio_buf->b_error = EIO;
	request->bio->bio_buf->b_flags |= B_ERROR;
	devstat_end_transaction_buf(&adp->stats, request->bio->bio_buf);
	biodone(request->bio);
	ad_free(request);
    }
    ata_reinit(adp->device->channel);
}

void
ad_reinit(struct ata_device *atadev)
{
    struct ad_softc *adp = atadev->driver;

    /* reinit disk parameters */
    ad_invalidatequeue(atadev->driver, NULL);
    ata_command(atadev, ATA_C_SET_MULTI, 0,
		adp->transfersize / DEV_BSIZE, 0, ATA_WAIT_READY);
    if (adp->device->mode >= ATA_DMA)
	ata_dmainit(atadev, ata_pmode(adp->device->param),
		    ata_wmode(adp->device->param),
		    ata_umode(adp->device->param));
    else
	ata_dmainit(atadev, ata_pmode(adp->device->param), -1, -1);
}

void
ad_print(struct ad_softc *adp) 
{
    if (bootverbose) {
	ata_prtdev(adp->device, "<%.40s/%.8s> ATA-%d disk at ata%d-%s\n", 
		   adp->device->param->model, adp->device->param->revision,
		   ad_version(adp->device->param->version_major), 
		   device_get_unit(adp->device->channel->dev),
		   (adp->device->unit == ATA_MASTER) ? "master" : "slave");

	ata_prtdev(adp->device,
		   "%lluMB (%llu sectors), %llu C, %u H, %u S, %u B\n",
		   (unsigned long long)(adp->total_secs /
		   ((1024L*1024L)/DEV_BSIZE)),
		   (unsigned long long) adp->total_secs,
		   (unsigned long long) (adp->total_secs /
		    (adp->heads * adp->sectors)),
		   adp->heads, adp->sectors, DEV_BSIZE);

	ata_prtdev(adp->device, "%d secs/int, %d depth queue, %s%s\n", 
		   adp->transfersize / DEV_BSIZE, adp->num_tags + 1,
		   (adp->flags & AD_F_TAG_ENABLED) ? "tagged " : "",
		   ata_mode2str(adp->device->mode));

	ata_prtdev(adp->device, "piomode=%d dmamode=%d udmamode=%d cblid=%d\n",
		   ata_pmode(adp->device->param), ata_wmode(adp->device->param),
		   ata_umode(adp->device->param), 
		   adp->device->param->hwres_cblid);

    }
    else
	ata_prtdev(adp->device,"%lluMB <%.40s> [%lld/%d/%d] at ata%d-%s %s%s\n",
		   (unsigned long long)(adp->total_secs /
		   ((1024L * 1024L) / DEV_BSIZE)),
		   adp->device->param->model,
		   (unsigned long long)(adp->total_secs /
		    (adp->heads*adp->sectors)),
		   adp->heads, adp->sectors,
		   device_get_unit(adp->device->channel->dev),
		   (adp->device->unit == ATA_MASTER) ? "master" : "slave",
		   (adp->flags & AD_F_TAG_ENABLED) ? "tagged " : "",
		   ata_mode2str(adp->device->mode));
}

static int
ad_version(u_int16_t version)
{
    int bit;

    if (version == 0xffff)
	return 0;
    for (bit = 15; bit >= 0; bit--)
	if (version & (1<<bit))
	    return bit;
    return 0;
}
