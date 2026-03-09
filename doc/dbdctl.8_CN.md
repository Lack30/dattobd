## 名称

dattobd - 控制 Datto 块设备内核模块。

## 概要

`dbdctl <子命令> [<参数>]`

## 描述

`dbdctl` 是用于管理 dattobd 内核模块的用户空间工具。它提供了一个接口来创建、删除、重载、转换和配置磁盘快照以及内核模块本身的某些参数。

本手册页简要描述了 `dbdctl`。更多详细信息请参阅位于 https://github.com/datto/dattobd 的 Git 仓库。

## 选项
    -c cache-size
         指定内存数据缓存可以增长到的大小（以 MB 为单位）。默认为 300 MB。

    -f fallocate
         指定磁盘上 COW 文件的最大大小。

## 子命令

### setup-snapshot

`dbdctl setup-snapshot [-c <缓存大小>] [-f <预分配大小>] <块设备> <COW 文件路径> <次设备号>`

设置 `<块设备>` 的快照，将所有 COW 数据保存到 `<COW 文件路径>`。快照设备将是 `/dev/datto<次设备号>`。次设备号将作为所有其他 `dbdctl` 命令的引用编号。`<COW 文件路径>` 必须是 `<块设备>` 上的路径。

### reload-snapshot

`dbdctl reload-snapshot [-c <缓存大小>] <块设备> <COW 文件> <次设备号>`

重新加载快照。此命令应在块设备挂载之前运行，在重启或驱动程序卸载之后。它通知内核驱动程序预期指定的块设备将重新上线。此命令要求快照之前在快照模式下干净地卸载。如果不是这种情况，快照在尝试上线时将被置于失败状态。次设备号将作为所有其他 `dbdctl` 命令的引用编号。

### reload-incremental

`dbdctl reload-incremental [-c <缓存大小>] <块设备> <COW 文件> <次设备号>`

重新加载处于增量模式的块设备。限制请参见 `reload-snapshot`。

### transition-to-incremental

`dbdctl transition-to-incremental <次设备号>`

将快照 COW 文件转换为增量模式，该模式仅追踪快照开始以来哪些块已更改。这将移除关联的快照设备。

### transition-to-snapshot

`dbdctl transition-to-snapshot [-f <预分配大小>] <COW 文件> <次设备号>`

将处于增量模式的块设备转换为快照模式。此调用确保在拆除增量和设置新快照之间不会丢失任何写入。新的快照数据将记录在 `<COW 文件>` 中。旧的 COW 文件在此之后仍然存在，可以使用 `update-img` 等工具仅高效复制更改的块。

### destroy

`dbdctl destroy <次设备号>`

干净且完整地移除快照或增量，取消关联的 COW 文件链接。

### reconfigure

`dbdctl reconfigure [-c <缓存大小>] <次设备号>`

允许您在快照在线时重新配置其各种参数。目前只有索引缓存大小（以 MB 为单位）可以动态更改。

### expand-cow-file

`dbdctl expand-cow-file <大小> <次设备号>`

在快照模式下扩展 COW 文件（以兆字节为单位）。

### reconfigure-auto-expand

`dbdctl reconfigure-auto-expand [-n <步数限制>] <步长> <次设备号>`

在快照模式下启用 COW 文件自动扩展，步长为 `<步长>`（以兆字节为单位）。自动扩展的工作方式是每步之后至少为文件系统的普通用户保留 `<保留空间>`（以兆字节为单位）的可用空间。

## 示例

`# dbdctl setup-snapshot /dev/sda1 /var/backup/datto 4`

此命令将在 `/dev/datto4` 设置一个新的 COW 快照设备，追踪 `/dev/sda1`。此块设备由在路径 `/var/backup/datto` 创建的新文件支持。

`# dbdctl transition-to-incremental 4`

将次设备号指定的快照转换为增量模式。

`# dbdctl transition-to-snapshot /var/backup/datto1 4`

干净地将增量转换为新的快照，使用 `/var/backup/datto1` 作为新的 COW 文件。此时可以进行第二次备份，可以使用 `dd` 等工具进行完整复制，或者如果存在之前的快照备份，可以使用 `update-img` 等工具进行增量复制。

`# dbdctl reconfigure -c 400 4`

将块设备重新配置为具有 400 MB 的内存索引缓存大小。

`# dbdctl destroy 4`

这将停止追踪 `/dev/sda1`，移除关联的 `/dev/datto4`（因为设备处于快照模式），删除支持它的 COW 文件，并执行所有其他清理工作。

`# dbdctl reload-snapshot /dev/sda1 /var/backup/datto1 4`

重启后，此命令可以在启动的早期阶段执行，在块设备以读写方式挂载之前。这将通知驱动程序预期一个块设备 `/dev/sda1` 将上线，该设备在快照模式下留下，COW 文件位于 `/var/backup/datto1`（相对于挂载点），并且重新加载的快照应在次设备号 4 上线。如果块设备上线时发现问题，此块设备将被置于失败状态，这将在 `/proc/datto-info` 中报告。

`# dbdctl reload-incremental /dev/sda5 /var/backup/datto1 4`

这与 `reload-snapshot` 作用相同，但针对的是在增量模式下留下的设备。

## 缺陷

## 作者

    Tom Caputi (tcaputi@datto.com)
