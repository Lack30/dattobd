// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * Binlog export hook interface. Events are produced from the incremental
 * pipeline (inc_handle_sset) so the hot write path is never blocked.
 * Alternative hook for "first-change-only" semantics: __cow_write_mapping()
 * in cow_manager.c when the mapping transitions from 0 to non-zero.
 */

#ifndef BINLOG_EXPORT_H_
#define BINLOG_EXPORT_H_

#include <linux/blk_types.h>

struct snap_device;

/**
 * binlog_export_blocks_changed() - Notify export layer that a range of blocks
 * was marked changed (incremental pipeline).
 * @dev: Snap device (incremental mode).
 * @block_start: First block index (4 KiB units).
 * @block_count: Number of contiguous blocks.
 *
 * Called from inc_handle_sset() after filler mappings are written. Does not
 * run on the hot write path. No-op until the full export path is implemented.
 */
void binlog_export_blocks_changed(const struct snap_device *dev, sector_t block_start,
				 sector_t block_count);

#endif /* BINLOG_EXPORT_H_ */
