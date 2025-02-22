package transport

const (
	// WebRoot root path of APIs
	WebRoot = "emp3r0r"
	// CheckInAPI agent send POST to this API to report its system info
	CheckInAPI = WebRoot + "/checkin"
	// MsgAPI duplex tunnel between agent and cc
	MsgAPI = WebRoot + "/msg"
	// ReverseShellAPI duplex tunnel between agent and cc
	ReverseShellAPI = WebRoot + "/rshell"
	// ProxyAPI proxy interface
	ProxyAPI = WebRoot + "/proxy"
	// FTPAPI file transfer
	FTPAPI = WebRoot + "/ftp"
	// FileAPI host some files
	FileAPI = WebRoot + "/www"
	// Static hosting
	WWW = "/www/"

	// OperatorRoot root path of control APIs
	OperatorRoot = "operator"
	// OperatorSetActiveAgent
	OperatorSetActiveAgent = OperatorRoot + "/set_active_agent"
	// OperatorSendCommand
	OperatorSendCommand = OperatorRoot + "/send_command"
	// OperatorSetActiveModule
	OperatorSetActiveModule = OperatorRoot + "/set_active_module"
	// OperatorModuleRun
	OperatorModuleRun = OperatorRoot + "/module_run"
	// OperatorModuleSetOption
	OperatorModuleSetOption = OperatorRoot + "/module_set_option"
)
