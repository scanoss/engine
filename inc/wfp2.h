// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * inc/wfp2.h
 *
 * WFP2 (token-aware) fingerprint generation.
 *
 * Copyright (C) 2018-2025 SCANOSS.COM
 */

#ifndef __WFP2_H
#define __WFP2_H

#include <stdint.h>

/**
 * @brief Compute the WFP2 (token-aware) snippet fingerprints of a source buffer.
 *
 * Mirrors the reference Go implementation (scanoss-go / go-minr snippetsx):
 * language detection -> comment removal -> token-aware normalization -> winnowing
 * (GRAM 20, WINDOW 40, CRC32C). The output hashes/lines must match, byte for byte,
 * the fingerprints the KB was mined with, otherwise nothing will match the wfp2 table.
 *
 * @param src source buffer (text)
 * @param src_len length of src in bytes
 * @param hashes output array of wfp2 hashes
 * @param lines output array of line numbers (paired with hashes)
 * @param limit maximum number of hashes to emit
 * @return number of hashes produced
 */
uint32_t winnowing_wfp2(char *src, long src_len, uint32_t *hashes, uint32_t *lines, long limit);

#endif
