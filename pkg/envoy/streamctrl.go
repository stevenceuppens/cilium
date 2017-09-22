package envoy

import (
	"log"
	"math"
	"sync"
)

type StreamControlCtx struct {
	wg       sync.WaitGroup
	handlers []*StreamControl
}

func (ctx *StreamControlCtx) Stop() {
	for _, ctrl := range ctx.handlers {
		ctrl.StopHandling()
	}
	// Wait for everyone to be done.
	ctx.wg.Wait()
}

// Versioned stream controller.
// 64-bit version numbers are assumed to never wrap around.
type StreamControl struct {
	name            string
	cond            sync.Cond // L mutex used to protect members below as well.
	handled         bool
	acked_version   uint64
	sent_version    uint64
	current_version uint64
}

func MakeStreamControl(name string) StreamControl {
	return StreamControl{
		name:            name,
		cond:            sync.Cond{L: &sync.Mutex{}},
		acked_version:   math.MaxUint64,
		sent_version:    0,
		current_version: 1,
	}
}

func (ctrl *StreamControl) Name() string {
	return ctrl.name
}

func (ctrl *StreamControl) CurrentVersion() uint64 {
	return ctrl.current_version
}

func (ctrl *StreamControl) Lock() {
	ctrl.cond.L.Lock()
}

func (ctrl *StreamControl) Unlock() {
	ctrl.cond.L.Unlock()
}

// update stream control based on received 'version'. Returns true if
// the current version should be sent.
// Lock must be held.
func (ctrl *StreamControl) updateVersion(version uint64) bool {
	// Bump current version UP to sync with the version history of the caller, if we receive
	// evidence for a version we have not sent yet. This can happen when we restart.
	if ctrl.sent_version < version {
		ctrl.current_version = version + 1
		log.Print(ctrl.name, " version bumped to ", ctrl.current_version)
	}

	// Roll back acked version if this is a NAK (== version is the same as the
	// previous acked version).
	if version == ctrl.acked_version {
		// NAK, send again
		ctrl.sent_version = version
		log.Print(ctrl.name, " NAK received, sending again after version ", version)
	}
	ctrl.acked_version = version // remember the last acked version

	return ctrl.current_version > ctrl.sent_version
}

func (ctrl *StreamControl) UpdateVersion(version uint64) bool {
	ctrl.cond.L.Lock()
	defer ctrl.cond.L.Unlock()
	return ctrl.updateVersion(version)
}

// 'handler()' is called to send the current version if it is later than 'version'
// Starts a handler gorouting on demand tracked by 'ctx'.
func (ctrl *StreamControl) startHandler(ctx *StreamControlCtx, handler func() error) {
	ctrl.handled = true
	ctx.handlers = append(ctx.handlers, ctrl)

	log.Print("Starting ", ctrl.name)

	ctx.wg.Add(1)
	go func() {
		defer ctx.wg.Done()
		ctrl.cond.L.Lock()
		for {
			// Quit waiting if we should stop or have something to send.
			// cond.Wait automatically unlocks and locks again.
			for ctrl.handled && ctrl.sent_version == ctrl.current_version {
				ctrl.cond.Wait()
			}
			if !ctrl.handled {
				break // end handling
			}
			// Send the current version
			if handler() == nil {
				ctrl.sent_version = ctrl.current_version
			}
		}
		ctrl.cond.L.Unlock()
	}()
}

// 'handler()' is called to send the current version if it is later than 'version'
// Starts a handler gorouting on demand tracked by 'ctx'.
func (ctrl *StreamControl) HandleVersion(ctx *StreamControlCtx, version uint64, handler func() error) {
	ctrl.cond.L.Lock()
	must_send := ctrl.updateVersion(version)

	// Start the handler if needed
	if must_send && !ctrl.handled {
		ctrl.startHandler(ctx, handler)
	}
	ctrl.cond.L.Unlock()

	if must_send {
		log.Print(ctrl.name, " version ", ctrl.current_version, " queued.")
		ctrl.cond.Signal()
	} else {
		log.Print(ctrl.name, " version ", ctrl.current_version, " acked.")
	}
}

func (ctrl *StreamControl) StopHandling() {
	ctrl.cond.L.Lock()
	ctrl.handled = false
	ctrl.cond.L.Unlock()
	ctrl.cond.Signal()
}

// f is called while the lock is held
func (ctrl *StreamControl) BumpVersionFunc(f func()) {
	if ctrl != nil {
		ctrl.cond.L.Lock()
		f()
		ctrl.current_version++
		ctrl.cond.L.Unlock()
		ctrl.cond.Signal()
	}
}

func (ctrl *StreamControl) BumpVersion() {
	if ctrl != nil {
		ctrl.cond.L.Lock()
		ctrl.current_version++
		ctrl.cond.L.Unlock()
		ctrl.cond.Signal()
	}
}
