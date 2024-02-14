package quic

import (
	"errors"
	"sort"
	"sync"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"
)

type framer interface {
	HasData() bool

	QueueControlFrame(wire.Frame)
	AppendControlFrames([]ackhandler.Frame, protocol.ByteCount, protocol.Version) ([]ackhandler.Frame, protocol.ByteCount)

	AddActiveStream(protocol.StreamID)
	AppendStreamFrames([]ackhandler.StreamFrame, protocol.ByteCount, protocol.Version) ([]ackhandler.StreamFrame, protocol.ByteCount)

	Handle0RTTRejection() error
}

const maxPathResponses = 256

type framerI struct {
	mutex sync.Mutex

	streamGetter streamGetter

	activeStreams map[protocol.StreamID]struct{}
	//streamQueue   ringbuffer.RingBuffer[protocol.StreamID]
	streamQueue []protocol.StreamID

	controlFrameMutex sync.Mutex
	controlFrames     []wire.Frame
	pathResponses     []*wire.PathResponseFrame
}

var _ framer = &framerI{}

func newFramer(streamGetter streamGetter) framer {
	return &framerI{
		streamGetter:  streamGetter,
		activeStreams: make(map[protocol.StreamID]struct{}),
	}
}

func (f *framerI) HasData() bool {
	f.mutex.Lock()
	hasData := len(f.streamQueue) > 0
	f.mutex.Unlock()
	if hasData {
		return true
	}
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	return len(f.controlFrames) > 0 || len(f.pathResponses) > 0
}

func (f *framerI) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	if pr, ok := frame.(*wire.PathResponseFrame); ok {
		// Only queue up to maxPathResponses PATH_RESPONSE frames.
		// This limit should be high enough to never be hit in practice,
		// unless the peer is doing something malicious.
		if len(f.pathResponses) >= maxPathResponses {
			return
		}
		f.pathResponses = append(f.pathResponses, pr)
		return
	}
	f.controlFrames = append(f.controlFrames, frame)
}

func (f *framerI) AppendControlFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	var length protocol.ByteCount
	// add a PATH_RESPONSE first, but only pack a single PATH_RESPONSE per packet
	if len(f.pathResponses) > 0 {
		frame := f.pathResponses[0]
		frameLen := frame.Length(v)
		if frameLen <= maxLen {
			frames = append(frames, ackhandler.Frame{Frame: frame})
			length += frameLen
			f.pathResponses = f.pathResponses[1:]
		}
	}

	for len(f.controlFrames) > 0 {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(v)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}
	return frames, length
}

func (f *framerI) AddActiveStream(id protocol.StreamID) {
	f.mutex.Lock()
	if _, ok := f.activeStreams[id]; !ok {
		f.streamQueue = append(f.streamQueue, id)
		f.activeStreams[id] = struct{}{}
		f.sortQueue()
	}
	f.mutex.Unlock()
}

func (f *framerI) sortQueue() {
	// Sort the queue by descending priority order
	sort.SliceStable(f.streamQueue, func(i int, j int) bool {
		str1, err := f.streamGetter.GetOrOpenSendStream(f.streamQueue[i])
		if str1 == nil || err != nil {
			return false // Push to the front so we can pop it
		}

		str2, err := f.streamGetter.GetOrOpenSendStream(f.streamQueue[j])
		if str2 == nil || err != nil {
			return true // Push to the front so we can pop it
		}

		return str1.getPriority() > str2.getPriority()
	})
}

func (f *framerI) AppendStreamFrames(frames []ackhandler.StreamFrame, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.StreamFrame, protocol.ByteCount) {
	startLen := len(frames)
	var length protocol.ByteCount
	f.mutex.Lock()

	// TODO perform this sort when SetPriority() is called
	f.sortQueue()

	// Record information about streams with the same priority
	priorityCurrent := 0 // The current priority value
	prioritySent := 0    // The number of sent streams with this priority
	priorityUnsent := 0  // The number of unsent streams with this priority

	i := 0

	// pop STREAM frames, until less than MinStreamFrameSize bytes are left in the packet
	for i < len(f.streamQueue) {
		id := f.streamQueue[i]
		// This should never return an error. Better check it anyway.
		// The stream will only be in the streamQueue, if it enqueued itself there.
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		// The stream can be nil if it completed after it said it had data.
		if str == nil || err != nil {
			delete(f.activeStreams, id)

			// Shift the remaining elements in the queue forward
			copy(f.streamQueue[i:], f.streamQueue[i+1:])
			f.streamQueue = f.streamQueue[:len(f.streamQueue)-1]

			// Don't increment i since we just removed an element
			continue
		}

		// Get the priority for the current stream
		priority := str.getPriority()
		full := protocol.MinStreamFrameSize+length > maxLen
		if full {
			// If we're full, see if the previous streams had the same priority
			if priority != priorityCurrent {
				// We can stop interating since we've found all streams with the same priority
				break
			}

			// Keep looping until this is no longer the case.
			priorityUnsent += 1
			i += 1

			continue
		}

		// See if the previous streams had the same priority
		if i == 0 || priority != priorityCurrent {
			// We just sent a new priority level; reset our counters
			priorityCurrent = priority
			priorityUnsent = 0
			prioritySent = 0
		}

		remainingLen := maxLen - length
		// For the last STREAM frame, we'll remove the DataLen field later.
		// Therefore, we can pretend to have more bytes available when popping
		// the STREAM frame (which will always have the DataLen set).
		remainingLen += quicvarint.Len(uint64(remainingLen))

		frame, ok, hasMoreData := str.popStreamFrame(remainingLen, v)
		// The frame can be "nil"
		// * if the receiveStream was canceled after it said it had data
		// * the remaining size doesn't allow us to add another STREAM frame
		if ok {
			frames = append(frames, frame)
			length += frame.Frame.Length(v)
		}
		if !hasMoreData {
			// no more data to send. Stream is not active any more
			delete(f.activeStreams, id)

			// Shift the remaining elements in the queue forward
			copy(f.streamQueue[i:], f.streamQueue[i+1:])
			f.streamQueue = f.streamQueue[:len(f.streamQueue)-1]

			// Don't increment i since we just removed an element
			continue
		}

		i += 1
		prioritySent += 1
	}

	if priorityUnsent > 0 && prioritySent > 0 {
		// There were some streams sent and some streams unsent within the same priority.
		// We want to swap the last `priorityUnsent` values with the prior `prioritySent` values.
		// This way we will round-robin streams with the same priority.
		swap := make([]protocol.StreamID, prioritySent)

		end := i
		middle := end - priorityUnsent
		start := middle - prioritySent

		copy(swap, f.streamQueue[start:middle+1])
		copy(f.streamQueue[start:], f.streamQueue[middle:end])
		copy(f.streamQueue[end-len(swap):], swap)

		// Example:
		// i = 7
		// streamQueue (priority): [ 7, 7, 5, 5, 5, 5, 5, 2, 2 ]
		// priorityUnset = 3
		// prioritySent = 2

		// We want to move index 2,3 to index 5,6 and index 4,5,6 to index 2,3,4
		// end = 7
		// middle = 4
		// start = 2

		// copy(swap, queue[2:5])
		// copy(queue[2:], queue[4:7])
		// copy(queue[5:], swap)
	}

	f.mutex.Unlock()
	if len(frames) > startLen {
		l := frames[len(frames)-1].Frame.Length(v)
		// account for the smaller size of the last STREAM frame
		frames[len(frames)-1].Frame.DataLenPresent = false
		length += frames[len(frames)-1].Frame.Length(v) - l
	}

	return frames, length
}

func (f *framerI) Handle0RTTRejection() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.controlFrameMutex.Lock()
	f.streamQueue = f.streamQueue[:0]
	for id := range f.activeStreams {
		delete(f.activeStreams, id)
	}
	var j int
	for i, frame := range f.controlFrames {
		switch frame.(type) {
		case *wire.MaxDataFrame, *wire.MaxStreamDataFrame, *wire.MaxStreamsFrame:
			return errors.New("didn't expect MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS frame to be sent in 0-RTT")
		case *wire.DataBlockedFrame, *wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
			continue
		default:
			f.controlFrames[j] = f.controlFrames[i]
			j++
		}
	}
	f.controlFrames = f.controlFrames[:j]
	f.controlFrameMutex.Unlock()
	return nil
}
