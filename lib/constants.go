package libunlynx

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"os"
	"time"

	"go.dedis.ch/onet/v3/simul/monitor"
)

func init() {
	timeout, err := time.ParseDuration(os.Getenv("CONN_TIMEOUT"))
	if err == nil {
		TIMEOUT = timeout
	} else {
		log.Warn("Couldn't parse CONN_TIMEOUT, using default value: ", TIMEOUT.String())
	}
}

// Global Variables
//______________________________________________________________________________________________________________________

// TIME is true if we use protocols with time measurements of computations.
var TIME = false

// VPARALLELIZE allows to choose the level of parallelization in the vector computations
const VPARALLELIZE = 100

// DIFFPRI enables the DRO protocol (Distributed Results Obfuscation)
const DIFFPRI = false

// TIMEOUT ddefines the default channel timeout
var TIMEOUT = 10 * time.Minute

// StartTimer starts measurement of time
func StartTimer(name string) *monitor.TimeMeasure {
	if TIME {
		return monitor.NewTimeMeasure(name)
	}
	return nil
}

// EndTimer finishes measurement of time
func EndTimer(timer *monitor.TimeMeasure) {
	if TIME {
		timer.Record()
	}
}

// WaitGroupWithError is like a sync.WaitGroup, with an error channel
type WaitGroupWithError struct {
	waiter  chan error
	counter uint
}

// NewWaitGroupWithError creates a new WaitGroupWithError for the given count
func NewWaitGroupWithError(count uint) WaitGroupWithError {
	return WaitGroupWithError{
		waiter:  make(chan error, count),
		counter: count,
	}
}

// Done mark the end of a goroutine, it has to be called, even with nil error
func (wg WaitGroupWithError) Done(err error) {
	wg.waiter <- err
}

// Wait waits for all expected goroutine to finish, returning the first error encountered
func (wg WaitGroupWithError) Wait() error {
	var ret error

	for i := uint(0); i < wg.counter; i++ {
		if err := <-wg.waiter; ret == nil && err != nil {
			ret = err
		}
	}

	return ret
}

// StartParallelize starts parallelization by instanciating number of threads
func StartParallelize(nbrWg uint) WaitGroupWithError {
	return NewWaitGroupWithError(nbrWg)
}

// StartParallelizeWithInt starts parallelization by instanciating number of threads, channelling an error if nbrWg < 0
func StartParallelizeWithInt(nbrWg int) WaitGroupWithError {
	wrongArg := nbrWg < 0

	if wrongArg {
		nbrWg = 1
	}

	ret := NewWaitGroupWithError(uint(nbrWg))

	if wrongArg {
		ret.Done(errors.New("parallelization with negative number of worker"))
	}

	return ret
}

// EndParallelize waits for a number of threads to finish
func EndParallelize(wg WaitGroupWithError) error {
	return wg.Wait()
}
