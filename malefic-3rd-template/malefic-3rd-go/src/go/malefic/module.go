package malefic

// GoModule is the low-level streaming interface.
// Use this directly only when you need bidirectional streaming (multiple responses per request).
// For simple request→response modules, implement GoModuleHandler instead.
type GoModule interface {
	Name() string
	Run(taskId uint32, input <-chan *Request, output chan<- *Response)
}

// GoModuleHandler is the simple interface for one-shot request→response modules.
// Implement this to avoid dealing with channels — just like check_request! on the Rust side.
type GoModuleHandler interface {
	Name() string
	Handle(taskId uint32, req *Request) (*Response, error)
}

// AsModule wraps a GoModuleHandler into a GoModule.
func AsModule(h GoModuleHandler) GoModule {
	return &handlerAdapter{h}
}

type handlerAdapter struct {
	handler GoModuleHandler
}

func (a *handlerAdapter) Name() string { return a.handler.Name() }

func (a *handlerAdapter) Run(taskId uint32, input <-chan *Request, output chan<- *Response) {
	for req := range input {
		resp, err := a.handler.Handle(taskId, req)
		if err != nil {
			output <- &Response{Error: err.Error()}
			continue
		}
		if resp != nil {
			output <- resp
		}
	}
}
