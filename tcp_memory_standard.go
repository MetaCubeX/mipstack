//go:build !with_low_memory

package mipstack

const (
	// Avoid spending a full later chunk on overflow from an undersized small spare.
	tcpFitSmallSendSpare = false
	// tcpReadChunkRetain keeps metadata for a modest receive burst after it
	// drains without retaining the payload backing or a multi-megabyte array of
	// slice headers on an idle connection.
	tcpReadChunkRetain = 64
	// tcpSendChunkInitial bounds the unused backing retained by an idle
	// connection after a small write. Later chunks in the same live send window
	// use tcpSendChunkMinimum so packet construction remains scatter-bounded.
	tcpSendChunkInitial = 2 * 1024
	// tcpReusableSendChunkLimit retains only a modest acknowledged send chunk.
	// Larger chunks are released so a completed bulk transfer does not pin its
	// former window.
	tcpReusableSendChunkLimit = 32 * 1024
)
