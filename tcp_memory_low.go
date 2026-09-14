//go:build with_low_memory

package mipstack

// Low-memory builds retain less unused backing while preserving on-demand
// allocation, active TCP windows, automatic growth and common buffer reuse.
// These are storage/cache bounds, not advertised TCP receive-window limits.
const (
	// Avoid spending a full later chunk on overflow from an undersized small spare.
	tcpFitSmallSendSpare = true
	// Keep ordinary short read bursts reusable, but release larger drained metadata.
	tcpReadChunkRetain = 32
	// The first live send chunk can be small. Later chunks keep their normal
	// minimum to preserve the bound on packet scatter/gather segments.
	tcpSendChunkInitial = 1024
	// Repeated moderate writes can retain one 16 KiB chunk. Larger acknowledged
	// chunks are released; unread and unacknowledged storage is never truncated.
	tcpReusableSendChunkLimit = 16 * 1024
)
