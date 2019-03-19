/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/avstring.h"
#include "libavutil/common.h"
#include "libavutil/opt.h"
#include "libavutil/aes.h"
#include "libavutil/encryption_info.h"

#include "bsf.h"
#include "bsf_internal.h"
#include "cbs.h"
#include "cbs_h264.h"
#include "cbs_h265.h"
#include "cbs_h2645.h"
#include "h264.h"
#include "hevc.h"

typedef struct CencCbcsContext {
    const AVClass *class;

    CodedBitstreamContext *cbc;
    CodedBitstreamFragment access_unit;
    struct AVAES *aes;
    AVEncryptionInfo *info;

    // options

    uint8_t *key;
    int      key_len;

    uint8_t *iv;
    int      iv_len;
} CencCbcsContext;

static int needs_encryption(AVBSFContext *bsf, CodedBitstreamUnit *nal)
{
    switch (bsf->par_in->codec_id) {
        case AV_CODEC_ID_H264:
            return nal->type == H264_NAL_SLICE ||
                   nal->type == H264_NAL_IDR_SLICE ||
                   nal->type == H264_NAL_AUXILIARY_SLICE;
        case AV_CODEC_ID_H265:
            switch (nal->type) {
                case HEVC_NAL_TRAIL_N:
                case HEVC_NAL_TRAIL_R:
                case HEVC_NAL_TSA_N:
                case HEVC_NAL_TSA_R:
                case HEVC_NAL_STSA_N:
                case HEVC_NAL_STSA_R:
                case HEVC_NAL_RADL_N:
                case HEVC_NAL_RADL_R:
                case HEVC_NAL_RASL_N:
                case HEVC_NAL_RASL_R:
                case HEVC_NAL_BLA_W_LP:
                case HEVC_NAL_BLA_W_RADL:
                case HEVC_NAL_BLA_N_LP:
                case HEVC_NAL_IDR_W_RADL:
                case HEVC_NAL_IDR_N_LP:
                case HEVC_NAL_CRA_NUT:
                    return 1;
            }
            break;
    }

    return 0;
}

static int apply_cbcs(CencCbcsContext *ctx, uint8_t *buf, int len, int skip)
{
    uint8_t iv[16];

    memcpy(iv, ctx->iv, 16); // av_aes_crypt updates the passed iv...

    while (len >= 16) {
        av_aes_crypt(ctx->aes, buf, buf, 1, iv, 0);

        buf += 16 * (1 + skip);
        len -= 16 * (1 + skip);
    }

    return 0;
}

static int cenc_cbcs_filter(AVBSFContext *bsf, AVPacket *pkt)
{
    CencCbcsContext *ctx = bsf->priv_data;
	CodedBitstreamFragment *au = &ctx->access_unit;
    int err, i;

    err = ff_bsf_get_packet_ref(bsf, pkt);
    if (err < 0)
        return err;

    err = av_packet_make_writable(pkt);
    if (err < 0)
        goto fail;

    if (ctx->cbc) {
        err = ff_cbs_read_packet(ctx->cbc, au, pkt);
        if (err < 0) {
            av_log(bsf, AV_LOG_ERROR, "Failed to read packet.\n");
            goto fail;
        }

        int subsample_count = 0;

        for (i = 0; i < au->nb_units; i++) {
            CodedBitstreamUnit *nal = &au->units[i];

            if (needs_encryption(bsf, nal)) {
				int offset = 32;

				if (bsf->par_in->codec_id == AV_CODEC_ID_H264) {
                    H264RawSlice *slice = nal->content;
                    offset = (slice->data - nal->data) + !!slice->data_bit_start; // TODO: handle emulation prevention bytes!!
                }
                else if (bsf->par_in->codec_id == AV_CODEC_ID_H265) {
                    H265RawSlice *slice = nal->content;
                    offset = (slice->data - nal->data) + !!slice->data_bit_start;
                }

                CodedBitstreamH2645Context *priv = ctx->cbc->priv_data;
				int len = priv->read_packet.nals[i].raw_size - offset;
				if (len < 0)
					len = 0;

				apply_cbcs(ctx, (uint8_t *)priv->read_packet.nals[i].raw_data + offset, len, 9);

                AVSubsampleEncryptionInfo *subsample = &ctx->info->subsamples[subsample_count++];
                subsample->bytes_of_clear_data = (priv->read_packet.nals[i].raw_data + offset) - pkt->data;
                subsample->bytes_of_protected_data = len;
            }
        }

		if (subsample_count) {
            ctx->info->subsample_count = subsample_count;

            size_t size;
            uint8_t *side_data = av_encryption_info_add_side_data(ctx->info, &size);
            av_packet_add_side_data(pkt, AV_PKT_DATA_ENCRYPTION_INFO, side_data, size);
		}
	} else {
		apply_cbcs(ctx, pkt->data, pkt->size, 0);
    }

    err = 0;
fail:
	if (ctx->cbc)
        ff_cbs_fragment_reset(au);

    if (err < 0)
        av_packet_unref(pkt);

    return err;
}

static int cenc_cbcs_init(AVBSFContext *bsf)
{
    CencCbcsContext *ctx = bsf->priv_data;
    CodedBitstreamFragment *au = &ctx->access_unit;
    int err;

    if (bsf->par_in->codec_type == AVMEDIA_TYPE_VIDEO) {
        switch (bsf->par_in->codec_id) {
            case AV_CODEC_ID_H264:
            case AV_CODEC_ID_H265:
                break; /* ok */

            default: {
                const AVCodecDescriptor *desc = avcodec_descriptor_get(bsf->par_in->codec_id);
                av_log(bsf, AV_LOG_ERROR, "Codec '%s' (%d) is not supported by the bitstream filter '%s'.\n",
                    desc ? desc->name : "unknown", bsf->par_in->codec_id, bsf->filter->name);
                return AVERROR(EINVAL);
            }
        }
    }

    // check options

    if (ctx->key_len != 16) {
        av_log(bsf, AV_LOG_ERROR, "Invalid key len. Must be 16 bytes.\n");
        err = AVERROR(EINVAL);
        goto fail;
    }

    if (ctx->iv_len != 16) {
        av_log(bsf, AV_LOG_ERROR, "Invalid IV len. Must be 16 byte.s\n");
        err = AVERROR(EINVAL);
        goto fail;
    }

    // prepare

    ctx->aes = av_aes_alloc();
    if (!ctx->aes) {
        err = AVERROR(ENOMEM);
        goto fail;
    }

    err = av_aes_init(ctx->aes, ctx->key, 128, 0);
    if (err < 0)
        goto fail;

    ctx->info = av_encryption_info_alloc(4, 16, ctx->iv_len);
    if (!ctx->info)
        goto fail;

    ctx->info->scheme = MKBETAG('c', 'b', 'c', 's');
    memcpy(ctx->info->iv, ctx->iv, 16);
    ctx->info->crypt_byte_block = 1;
    ctx->info->skip_byte_block = 9;

    if (bsf->par_in->codec_id == AV_CODEC_ID_H264 || bsf->par_in->codec_id == AV_CODEC_ID_H265) {
        err = ff_cbs_init(&ctx->cbc, bsf->par_in->codec_id, bsf);
        if (err < 0)
            goto fail;

        if (bsf->par_in->extradata) {
            err = ff_cbs_read_extradata(ctx->cbc, au, bsf->par_in);
            if (err < 0) {
                av_log(bsf, AV_LOG_ERROR, "Failed to read extradata.\n");
                goto fail;
            }

            CodedBitstreamH2645Context *priv = ctx->cbc->priv_data;

            priv->mp4 = 1;
            priv->nal_length_size = 4;
        }
    }

    err = 0;
fail:
    if (ctx->cbc)
        ff_cbs_fragment_reset(au);

    if (ctx->key && ctx->key_len) {
        // clear key from memory
        memset(ctx->key, 0, ctx->key_len);
        ctx->key_len = 0;
    }

    return err;
}

static void cenc_cbcs_close(AVBSFContext *bsf)
{
    CencCbcsContext *ctx = bsf->priv_data;

    if (ctx->aes) {
        uint8_t key[16] = { 0 };
        av_aes_init(ctx->aes, key, 128, 1); // clear encryption key from memory
        av_freep(&ctx->aes);
    }

    if (ctx->cbc) {
        ff_cbs_fragment_free(&ctx->access_unit);
        ff_cbs_close(&ctx->cbc);
    }

    av_encryption_info_free(ctx->info);
}

#define OFFSET(x) offsetof(CencCbcsContext, x)
static const AVOption cenc_cbcs_options[] = {
    { "key", "Encryption key.", OFFSET(key), AV_OPT_TYPE_BINARY, .flags = AV_OPT_FLAG_BSF_PARAM },
    { "iv", "Encryption IV.", OFFSET(iv), AV_OPT_TYPE_BINARY, .flags = AV_OPT_FLAG_BSF_PARAM },

    { NULL }
};

static const AVClass cenc_cbcs_class = {
    .class_name = "cenc_cbcs_bsf",
    .item_name  = av_default_item_name,
    .option     = cenc_cbcs_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const AVBitStreamFilter ff_cenc_cbcs_bsf = {
    .name           = "cenc_cbcs",
    .priv_data_size = sizeof(CencCbcsContext),
    .priv_class     = &cenc_cbcs_class,
    .init           = &cenc_cbcs_init,
    .close          = &cenc_cbcs_close,
    .filter         = &cenc_cbcs_filter,
};
