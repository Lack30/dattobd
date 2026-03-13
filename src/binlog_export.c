// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * Binlog export hook implementation. Hook is installed in inc_handle_sset();
 * full ring buffer and read/poll interface to be added in a later phase.
 */

#include "binlog_export.h"
#include "snap_device.h"

void binlog_export_blocks_changed(const struct snap_device *dev, sector_t block_start,
                                  sector_t block_count)
{
    /* Stub: no-op until export queue and user-space read path exist. */
    (void)dev;
    (void)block_start;
    (void)block_count;
}
