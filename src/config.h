/*
 * 根据特性检测结果派生模块内部使用的配置开关。
 */

#if defined HAVE_BDEV_FILE_OPEN_BY_PATH && defined HAVE_FILE_BDEV

#define USE_BDEV_AS_FILE

#endif
