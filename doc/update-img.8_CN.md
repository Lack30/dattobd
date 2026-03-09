## 名称

update-img - 使用 dattobd COW 文件更新备份镜像

## 概要

`update-img <快照设备> <COW 文件> <镜像文件>`

## 描述

`update-img` 是一个简单的工具，用于高效更新由 dattobd 内核模块创建的备份镜像。它使用 dattobd 增量状态遗留的 COW 文件来高效更新现有的备份镜像。有关示例用例，请参阅 `dbdctl` 的手册页。

## 示例

`# update-img /dev/datto4 /var/backup/datto1 /mnt/data/backup-img`

此命令将使用 `/var/backup/datto1` 指示的更改块从 `/dev/datto4` 更新之前备份的快照 `/mnt/data/backup-img`。

**注意**：`<快照设备>` 必须是 `<镜像文件>` 复制来源的快照的**下一个**快照。

## 缺陷

## 作者

    Tom Caputi (tcaputi@datto.com)
