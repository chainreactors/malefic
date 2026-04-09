package malefic

import "sync"

var registeredModule GoModule

func RegisterModule(m GoModule) { registeredModule = m }
func GetModule() GoModule      { return registeredModule }

// Session holds per-task channels for bidirectional streaming.
type Session struct {
	Input  chan *Request
	Output chan *Response
	Done   chan struct{}
}

var sessions sync.Map // map[uint32]*Session

// GetOrCreateSession returns the session for taskId, creating one on first access.
func GetOrCreateSession(taskId uint32) *Session {
	if v, ok := sessions.Load(taskId); ok {
		return v.(*Session)
	}
	s := &Session{
		Input:  make(chan *Request, 16),
		Output: make(chan *Response, 16),
		Done:   make(chan struct{}),
	}
	actual, loaded := sessions.LoadOrStore(taskId, s)
	if loaded {
		return actual.(*Session)
	}
	go func() {
		defer close(s.Done)
		defer close(s.Output)
		registeredModule.Run(taskId, s.Input, s.Output)
	}()
	return s
}

// DeleteSession removes the session for taskId.
func DeleteSession(taskId uint32) {
	sessions.Delete(taskId)
}

// CloseSessionInput closes the input channel for the given task.
func CloseSessionInput(taskId uint32) {
	v, ok := sessions.Load(taskId)
	if !ok {
		return
	}
	s := v.(*Session)
	close(s.Input)
}

// BridgeSend deserializes data into a Request and sends it to the session.
// Returns 0 on success, -1 on failure.
func BridgeSend(taskId uint32, data []byte) int {
	s := GetOrCreateSession(taskId)
	req := &Request{}
	if err := req.UnmarshalVT(data); err != nil {
		return -1
	}
	select {
	case s.Input <- req:
		return 0
	case <-s.Done:
		return -1
	}
}

// BridgeRecv reads the next response from the session.
// Returns (data, status) where status: 0=ok, 1=done, 2=marshal error.
func BridgeRecv(taskId uint32) ([]byte, int) {
	s := GetOrCreateSession(taskId)
	resp, ok := <-s.Output
	if !ok {
		DeleteSession(taskId)
		return nil, 1
	}
	out, err := resp.MarshalVT()
	if err != nil {
		return nil, 2
	}
	return out, 0
}
