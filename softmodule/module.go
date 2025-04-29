package softmodule

import (
	"strconv"

	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

type UnimplementedCommandError struct {
	CommandType commands.CommandType
}

func (e *UnimplementedCommandError) Error() string {
	return "unimplemented command: " + strconv.Itoa(int(e.CommandType))
}

type Module struct{}

func New() *Module {
	return &Module{}
}

// Request executes a command on the HSM and returns the binary response
func (m *Module) Request(command *commands.CommandMessage) ([]byte, error) {
	switch command.CommandType {
	default:
		return nil, &UnimplementedCommandError{command.CommandType}
	}
}

// GetStatus requests the status of the HSM connector (not working for direct USB)
func (m *Module) GetStatus() (*connector.StatusResponse, error) {
	panic("not implemented") // TODO: Implement
}
