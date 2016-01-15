/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

/**
 * vendor specific
 */

#if VENDOR_ID == 4098
#define IS_AMD
#elif VENDOR_ID == 4318
#define IS_NV
#elif VENDOR_ID == 16925952
#define IS_APPLE
#else
#define IS_GENERIC
#endif

/**
 * AMD specific
 */

#ifdef IS_AMD
#pragma OPENCL EXTENSION cl_amd_media_ops  : enable
#pragma OPENCL EXTENSION cl_amd_media_ops2 : enable
#endif

/**
 * NV specific
 */

#ifdef IS_NV
#endif

/**
 * APPLE specific
 */

#ifdef IS_APPLE
#define IS_GENERIC
#define __L
#define __C const
#else
#define __L __local
#define __C __constant
#endif
