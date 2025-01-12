package agent

// Code taken from crypto/x/ssh/agent

const (
	// 3.7 Key constraint identifiers
	agentConstrainLifetime = 1
	agentConstrainConfirm  = 2
	// Constraint extension identifier up to version 2 of the protocol. A
	// backward incompatible change will be required if we want to add support
	// for SSH_AGENT_CONSTRAIN_MAXSIGN which uses the same ID.
	// agentConstrainExtensionV00 = 3
	// Constraint extension identifier in version 3 and later of the protocol.
	// agentConstrainExtension = 255
)

// type constrainExtensionAgentMsg struct {
// 	ExtensionName    string `sshtype:"255|3"`
// 	ExtensionDetails []byte

// 	// Rest is a field used for parsing, not part of message
// 	Rest []byte `ssh:"rest"`
// }

// 3.7 Key constraint identifiers
type constrainLifetimeAgentMsg struct {
	LifetimeSecs uint32 `sshtype:"1"`
}

// func parseConstraints(constraints []byte) (lifetimeSecs uint32, confirmBeforeUse bool, extensions []sshagent.ConstraintExtension, err error) {
// 	for len(constraints) != 0 {
// 		switch constraints[0] {
// 		case agentConstrainLifetime:
// 			lifetimeSecs = binary.BigEndian.Uint32(constraints[1:5])
// 			constraints = constraints[5:]
// 		case agentConstrainConfirm:
// 			confirmBeforeUse = true
// 			constraints = constraints[1:]
// 		// case agentConstrainExtension, agentConstrainExtensionV00:
// 		// 	var msg constrainExtensionAgentMsg
// 		// 	if err = ssh.Unmarshal(constraints, &msg); err != nil {
// 		// 		return 0, false, nil, err
// 		// 	}
// 		// 	extensions = append(extensions, sshagent.ConstraintExtension{
// 		// 		ExtensionName:    msg.ExtensionName,
// 		// 		ExtensionDetails: msg.ExtensionDetails,
// 		// 	})
// 		// 	constraints = msg.Rest
// 		default:
// 			return 0, false, nil, fmt.Errorf("unknown constraint type: %d", constraints[0])
// 		}
// 	}
// 	return
// }

// func setConstraints(key *key.SSHTPMKey, constraintBytes []byte) error {
// 	lifetimeSecs, confirmBeforeUse, constraintExtensions, err := parseConstraints(constraintBytes)
// 	if err != nil {
// 		return err
// 	}

// 	key.LifetimeSecs = lifetimeSecs
// 	key.ConfirmBeforeUse = confirmBeforeUse
// 	key.ConstraintExtensions = constraintExtensions
// 	return nil
// }
