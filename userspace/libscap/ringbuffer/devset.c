#include "devset.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "strl.h"
#include "../scap.h"
#include "scap_assert.h"

int32_t devset_init(struct scap_device_set *devset, size_t num_devs, char *lasterr)
{
	devset->m_ndevs = num_devs;

	devset->m_devs = (scap_device*) calloc(sizeof(scap_device), devset->m_ndevs);
	if(!devset->m_devs)
	{
		strlcpy(lasterr, "error allocating the device handles", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	for(size_t j = 0; j < num_devs; ++j)
	{
		devset->m_devs[j].m_buffer = INVALID_MAPPING;
		devset->m_devs[j].m_bufinfo = INVALID_MAPPING;
		devset->m_devs[j].m_bufstatus = INVALID_MAPPING;
		devset->m_devs[j].m_fd = INVALID_FD;
		devset->m_devs[j].m_bufinfo_fd = INVALID_FD;
		devset->m_devs[j].m_lastreadsize = 0;
		devset->m_devs[j].m_sn_len = 0;
	}
	devset->m_buffer_empty_wait_time_us = BUFFER_EMPTY_WAIT_TIME_US_START;
	devset->m_lasterr = lasterr;
	devset->m_alloc_devs = num_devs;

	return SCAP_SUCCESS;
}

int32_t devset_grow(struct scap_device_set *devset, size_t num_devs, char *lasterr)
{
	devset->m_ndevs = num_devs;
	scap_device *devs, *orig_devs = devset->m_devs;

	if(devset->m_alloc_devs >= num_devs)
	{
		return SCAP_SUCCESS;
	}

	// don't touch m_devs from another thread while we're reallocating
	//
	// Note: this is only designed to guard a single writer against a single reader
	// (i.e. one thread calling devset_grow, another handing out buffers from
	// an allocated m_devs array)
	devset->m_devs = NULL;
	__sync_synchronize();

	devs = (scap_device *)realloc(orig_devs, sizeof(scap_device) * devset->m_ndevs);
	if(!devs)
	{
		devset->m_devs = orig_devs;
		strlcpy(lasterr, "error allocating the device handles", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	for(size_t j = devset->m_alloc_devs; j < num_devs; ++j)
	{
		memset(&devs[j], 0, sizeof devs[j]);
		devs[j].m_buffer = INVALID_MAPPING;
		devs[j].m_bufinfo = INVALID_MAPPING;
		devs[j].m_bufstatus = INVALID_MAPPING;
		devs[j].m_fd = INVALID_FD;
		devs[j].m_bufinfo_fd = INVALID_FD;
		devs[j].m_lastreadsize = 0;
		devs[j].m_sn_len = 0;
		devs[j].m_state = DEV_CLOSED;
	}

	devset->m_devs = devs;

	// ensure m_devs is written before m_alloc_devs
	__sync_synchronize();

	devset->m_alloc_devs = num_devs;

	return SCAP_SUCCESS;
}

void devset_close_device(struct scap_device *dev)
{
	devset_munmap(dev->m_buffer, dev->m_mmap_size);
	devset_munmap(dev->m_bufinfo, dev->m_bufinfo_size);
	devset_close(dev->m_fd);
	devset_close(dev->m_bufinfo_fd);
}

void devset_free(struct scap_device_set *devset)
{
	if(devset == NULL || devset->m_devs == NULL)
	{
		return;
	}

	uint32_t j;
	for(j = 0; j < devset->m_ndevs; j++)
	{
		struct scap_device *dev = &devset->m_devs[j];
		devset_close_device(dev);
	}
	free(devset->m_devs);
}
