package conntrack

import (
	"math"
	_ "net/http/pprof"
)

type DestinationKey struct {
	Port     uint16
	Protocol uint8
}

type UIntCounter uint16

type DestinationStatistics struct {
	Failure UIntCounter
	Success UIntCounter
	Unknown UIntCounter
}

type DestinationState struct {
	Up          bool
	Connections ConnectionStateMap
}

func (s DestinationState) Empty() bool {
	return !s.Up && len(s.Connections) == 0
}

type ConnectionStateMap map[DestinationKey]DestinationStatistics

func (t ConnectionStateMap) Failure(protocol uint8, port uint16) (UIntCounter, UIntCounter) {
	if t == nil {
		return 1, 0
	}
	key := DestinationKey{Port: port, Protocol: protocol}
	stats := t[key]
	stats.Unknown = 0
	stats.Success = 0
	stats.Failure++
	// handle overflow
	if stats.Failure == 0 {
		stats.Failure = math.MaxUint16
	}
	t[key] = stats
	return stats.Failure, stats.Success
}

func (t ConnectionStateMap) Success(protocol uint8, port uint16) (UIntCounter, UIntCounter, bool) {
	if t == nil {
		return 0, 0, false
	}
	key := DestinationKey{Port: port, Protocol: protocol}
	stats, ok := t[key]
	if !ok {
		return 0, 0, false
	}
	stats.Unknown = 0
	stats.Success++
	// handle overflow
	if stats.Success == 0 {
		stats.Success = math.MaxUint16
	}
	t[key] = stats
	return stats.Failure, stats.Success, true
}
