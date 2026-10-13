/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! RFC 2198 redundant audio as a client's microphone sends it: where each block of a payload
//! sits, before anything is decoded. Nothing here reaches outside the module, so a fuzz build
//! (`fuzz/`) compiles it on its own.

/// Max redundant copies per frame and RED history depth.
pub(crate) const RED_MAX_DISTANCE: i32 = 4;

/// The blocks of a payload, oldest first, as `(ts, start, len)`; `red_blocks` says how many.
pub(crate) type Blocks = [(i64, usize, usize); RED_MAX_DISTANCE as usize + 1];

/// The blocks of an RFC 2198 payload, oldest first, as `(ts, start, len)` within it: each
/// redundant block at `primary_ts` less its 14-bit offset (an empty one left out), then the
/// primary, which is whatever bytes remain. `None` for a payload whose headers or blocks run
/// past it, or that carries more than `RED_MAX_DISTANCE` redundant blocks.
pub(crate) fn red_blocks(payload: &[u8], primary_ts: i64) -> Option<(Blocks, usize)> {
    let n = payload.len();
    let mut i = 0usize;
    let mut offs = [0i64; RED_MAX_DISTANCE as usize];
    let mut lens = [0usize; RED_MAX_DISTANCE as usize];
    let mut nh = 0usize;
    while i < n && (payload[i] & 0x80) != 0 {
        if i + 4 > n || nh >= RED_MAX_DISTANCE as usize {
            return None;
        }
        let field = ((payload[i + 1] as u32) << 16)
            | ((payload[i + 2] as u32) << 8)
            | (payload[i + 3] as u32);
        offs[nh] = ((field >> 10) & 0x3FFF) as i64;
        lens[nh] = (field & 0x3FF) as usize;
        nh += 1;
        i += 4;
    }
    if i >= n {
        return None;
    }
    i += 1;

    let mut frames: Blocks = [(0, 0, 0); RED_MAX_DISTANCE as usize + 1];
    let mut nf = 0usize;
    for k in 0..nh {
        if i + lens[k] > n {
            return None;
        }
        if lens[k] > 0 {
            frames[nf] = (primary_ts - offs[k], i, lens[k]);
            nf += 1;
        }
        i += lens[k];
    }
    frames[nf] = (primary_ts, i, n - i);
    nf += 1;
    Some((frames, nf))
}
