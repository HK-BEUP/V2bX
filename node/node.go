package node

import (
	"fmt"
"errors"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
)

type Node struct {
	controllers []*Controller
}

func New() *Node {
	return &Node{}
}

func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) error {
	n.controllers = make([]*Controller, len(nodes))
	for i := range nodes {
		p, err := panel.New(&nodes[i].ApiConfig)
		if err != nil {
			return err
		}
		// Register controller service
		n.controllers[i] = NewController(core, p, &nodes[i].Options)
		err = n.controllers[i].Start()
		if err != nil {
			return fmt.Errorf("start node controller [%s-%s-%d] error: %s",
				nodes[i].ApiConfig.APIHost,
				nodes[i].ApiConfig.NodeType,
				nodes[i].ApiConfig.NodeID,
				err)
		}
	}
	return nil
}

func (n *Node) Close() error {
 var failures []error
	for _, c := range n.controllers {
 if c == nil { continue }
		err := c.Close()
		if err != nil {
			failures = append(failures, err)
		}
	}
if len(failures)>0 { return errors.Join(failures...) }
 n.controllers = nil
 return nil
}
