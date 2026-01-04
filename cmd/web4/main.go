// cmd/web4/main.go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"web4mvp/internal/crypto"
	"web4mvp/internal/network"
	"web4mvp/internal/proto"
	"web4mvp/internal/store"
)

func die(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".web4mvp")
}

func writeMsg(outPath string, data []byte) error {
	return os.WriteFile(outPath, data, 0600)
}

func findContractByID(st *store.Store, cid [32]byte) (*proto.Contract, error) {
	cs, err := st.ListContracts()
	if err != nil {
		return nil, err
	}
	for i := range cs {
		id := proto.ContractID(cs[i].IOU)
		if bytes.Equal(id[:], cid[:]) {
			return &cs[i], nil
		}
	}
	return nil, fmt.Errorf("contract not found")
}

func e2eSeal(msgType string, contractID [32]byte, reqNonce uint64, peerEdPub, payload []byte) ([]byte, []byte, error) {
	ephPriv, ephPub, err := crypto.GenerateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	peerXPub, err := crypto.Ed25519PubToX25519(peerEdPub)
	if err != nil {
		return nil, nil, err
	}
	shared, err := crypto.X25519Shared(ephPriv, peerXPub)
	if err != nil {
		return nil, nil, err
	}
	key, err := crypto.DeriveKeyE(shared, "web4:v0:e2e:"+msgType, crypto.XKeySize)
	if err != nil {
		return nil, nil, err
	}
	nonce := e2eNonce(contractID, reqNonce, ephPub)
	sealed, err := crypto.XSealWithNonce(key, nonce, payload, nil)
	if err != nil {
		return nil, nil, err
	}
	return ephPub, sealed, nil
}

func e2eNonce(contractID [32]byte, reqNonce uint64, ephPub []byte) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], reqNonce)
	buf := make([]byte, 0, len("web4:v0:nonce|")+32+8+len(ephPub))
	buf = append(buf, []byte("web4:v0:nonce|")...)
	buf = append(buf, contractID[:]...)
	buf = append(buf, tmp[:]...)
	buf = append(buf, ephPub...)
	sum := crypto.SHA3_256(buf)
	return sum[:crypto.XNonceSize]
}

func recvData(data []byte, st *store.Store) {
	var hdr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		die("decode message type failed", err)
	}

	switch hdr.Type {
	case proto.MsgTypeContractOpen:
		m, err := proto.DecodeContractOpenMsg(data)
		if err != nil {
			die("decode contract open failed", err)
		}
		c, err := proto.ContractFromOpenMsg(m)
		if err != nil {
			die("invalid contract open", err)
		}
		if err := st.AddContract(c); err != nil {
			die("store contract failed", err)
		}
		id := proto.ContractID(c.IOU)
		fmt.Println("RECV OPEN", hex.EncodeToString(id[:]))

	case proto.MsgTypeRepayReq:
		m, err := proto.DecodeRepayReqMsg(data)
		if err != nil {
			die("decode repay request failed", err)
		}
		if err := st.AddRepayReq(m); err != nil {
			die("store repay request failed", err)
		}
		fmt.Println("RECV REPAY-REQ", m.ContractID)

	case proto.MsgTypeAck:
		m, err := proto.DecodeAckMsg(data)
		if err != nil {
			die("decode ack failed", err)
		}
		a, sigA, err := proto.AckFromMsg(m)
		if err != nil {
			die("invalid ack", err)
		}
		if a.Decision == 1 {
			if err := st.MarkClosed(a.ContractID, false); err != nil {
				die("mark closed failed", err)
			}
		}
		if err := st.AddAck(a, sigA); err != nil {
			die("store ack failed", err)
		}
		fmt.Println("RECV ACK", m.ContractID)

	default:
		die("unknown message type", fmt.Errorf("%s", hdr.Type))
	}
}
func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: web4 <keygen|open|list|close|ack|recv|quic-listen|quic-send>")
		os.Exit(1)
	}

	root := homeDir()
	_ = os.MkdirAll(root, 0700)

	st := store.New(
		filepath.Join(root, "contracts.jsonl"),
		filepath.Join(root, "acks.jsonl"),
		filepath.Join(root, "repayreqs.jsonl"),
	)

	switch os.Args[1] {

	case "keygen":
		pub, priv, err := crypto.GenKeypair()
		if err != nil {
			die("keygen failed", err)
		}
		if err := crypto.SaveKeypair(root, pub, priv); err != nil {
			die("save keys failed", err)
		}
		fmt.Println("OK keypair generated")
		fmt.Println("pub:", hex.EncodeToString(pub))

	case "open":
		fs := flag.NewFlagSet("open", flag.ExitOnError)
		toHex := fs.String("to", "", "counterparty pubkey hex")
		amount := fs.Uint64("amount", 0, "amount")
		nonce := fs.Uint64("nonce", 0, "nonce (monotonic per counterparty)")
		outPath := fs.String("out", "", "write ContractOpenMsg to file and exit")
		_ = fs.Parse(os.Args[2:])

		pub, priv, err := crypto.LoadKeypair(root)
		if err != nil {
			die("load keys failed", err)
		}
		to, err := hex.DecodeString(*toHex)
		if err != nil || len(to) != crypto.PubLen {
			die("invalid --to pubkey", fmt.Errorf("need %d bytes hex", crypto.PubLen))
		}

		iou := proto.IOU{Creditor: to, Debtor: pub, Amount: *amount, Nonce: *nonce}
		cid := proto.ContractID(iou)
		credHex := hex.EncodeToString(to)
		debtHex := hex.EncodeToString(pub)
		payload, err := proto.EncodeOpenPayload(credHex, debtHex, *amount, *nonce)
		if err != nil {
			die("encode open payload failed", err)
		}
		ephPub, sealed, err := e2eSeal(proto.MsgTypeContractOpen, cid, 0, to, payload)
		if err != nil {
			die("e2e seal failed", err)
		}

		// v0.0.2: sign over SHA3_256(message)
		iouMsg := proto.OpenSignBytes(iou, ephPub, sealed)
		sigB := crypto.Sign(priv, crypto.SHA3_256(iouMsg))

		// NOTE: in real life creditor also signs; for MVP we allow "half-open" then later attach creditor sig.
		c := proto.Contract{
			IOU:          iou,
			SigCred:      nil,
			SigDebt:      sigB,
			EphemeralPub: ephPub,
			Sealed:       sealed,
			Status:       "OPEN",
		}
		if err := st.AddContract(c); err != nil {
			die("store failed", err)
		}
		if *outPath != "" {
			msg := proto.ContractOpenMsgFromContract(c)
			data, err := proto.EncodeContractOpenMsg(msg)
			if err != nil {
				die("encode message failed", err)
			}
			if err := writeMsg(*outPath, data); err != nil {
				die("write message failed", err)
			}
			return
		}
		fmt.Println("OPEN", hex.EncodeToString(cid[:]))

	case "list":
		cs, err := st.ListContracts()
		if err != nil {
			die("list failed", err)
		}
		for _, c := range cs {
			id := proto.ContractID(c.IOU)
			fmt.Printf("%s  %s  amt=%d nonce=%d\n", c.Status, hex.EncodeToString(id[:]), c.IOU.Amount, c.IOU.Nonce)
		}

	case "close":
		fs := flag.NewFlagSet("close", flag.ExitOnError)
		idHex := fs.String("id", "", "contract id hex")
		reqNonce := fs.Uint64("reqnonce", 1, "request nonce")
		outPath := fs.String("out", "", "write RepayReqMsg to file and exit")
		_ = fs.Parse(os.Args[2:])

		pub, priv, err := crypto.LoadKeypair(root)
		if err != nil {
			die("load keys failed", err)
		}
		idBytes, err := hex.DecodeString(*idHex)
		if err != nil || len(idBytes) != 32 {
			die("invalid --id", fmt.Errorf("need 32 bytes hex"))
		}
		var cid [32]byte
		copy(cid[:], idBytes)

		c, err := findContractByID(st, cid)
		if err != nil {
			die("contract lookup failed", err)
		}
		if !bytes.Equal(c.IOU.Debtor, pub) {
			die("debtor mismatch", fmt.Errorf("only debtor can close"))
		}

		req := proto.RepayReq{ContractID: cid, ReqNonce: *reqNonce, Close: true}
		payload, err := proto.EncodeRepayPayload(*idHex, *reqNonce, true)
		if err != nil {
			die("encode repay payload failed", err)
		}
		ephPub, sealed, err := e2eSeal(proto.MsgTypeRepayReq, cid, *reqNonce, c.IOU.Creditor, payload)
		if err != nil {
			die("e2e seal failed", err)
		}

		// v0.0.2: sign over SHA3_256(message)
		reqMsg := proto.RepayReqSignBytes(req, ephPub, sealed)
		sig := crypto.Sign(priv, crypto.SHA3_256(reqMsg))

		_ = pub // (debtor pub already in key file)

		if *outPath != "" {
			msg := proto.RepayReqMsgFromReq(req, sig, ephPub, sealed)
			data, err := proto.EncodeRepayReqMsg(msg)
			if err != nil {
				die("encode message failed", err)
			}
			if err := writeMsg(*outPath, data); err != nil {
				die("write message failed", err)
			}
			return
		}

		fmt.Println("SEND repay-request")
		fmt.Println("contract:", *idHex)
		fmt.Println("reqnonce:", *reqNonce)
		fmt.Println("sigB:", hex.EncodeToString(sig))
		fmt.Println("(paste this to the creditor, then they run: web4 ack --id <id> --reqnonce <n> --sigb <hex>)")

	case "ack":
		fs := flag.NewFlagSet("ack", flag.ExitOnError)
		idHex := fs.String("id", "", "contract id hex")
		reqNonce := fs.Uint64("reqnonce", 1, "request nonce")
		sigBHex := fs.String("sigb", "", "debtor signature hex on RepayReq")
		decision := fs.Int("decision", 1, "1=accept 0=reject")
		forget := fs.Bool("forget", false, "if accept, mark closed (and optionally forget)")
		outPath := fs.String("out", "", "write AckMsg to file and exit")
		_ = fs.Parse(os.Args[2:])

		if *decision != 0 && *decision != 1 {
			die("invalid decision", fmt.Errorf("need 0 or 1"))
		}
		if *decision == 0 && *forget {
			die("invalid forget", fmt.Errorf("forget only allowed on accept"))
		}

		pubA, privA, err := crypto.LoadKeypair(root)
		if err != nil {
			die("load keys failed", err)
		}
		idBytes, err := hex.DecodeString(*idHex)
		if err != nil || len(idBytes) != 32 {
			die("invalid --id", fmt.Errorf("need 32 bytes hex"))
		}
		var cid [32]byte
		copy(cid[:], idBytes)

		reqMsg, err := st.FindRepayReq(*idHex, *reqNonce)
		if err != nil {
			die("find repay request failed", err)
		}
		if reqMsg == nil {
			die("missing repay request", fmt.Errorf("recv a repay request first"))
		}
		if *sigBHex == "" {
			if reqMsg.SigB == "" {
				die("missing sigb", fmt.Errorf("provide --sigb or recv a repay request"))
			}
			*sigBHex = reqMsg.SigB
		}
		sigB, err := hex.DecodeString(*sigBHex)
		if err != nil {
			die("invalid sigb", err)
		}

		c, err := findContractByID(st, cid)
		if err != nil {
			die("contract lookup failed", err)
		}
		if !bytes.Equal(c.IOU.Creditor, pubA) {
			die("creditor mismatch", fmt.Errorf("only creditor can ack"))
		}
		ephPub, sealed, err := proto.DecodeSealedFields(reqMsg.EphemeralPub, reqMsg.Sealed)
		if err != nil {
			die("invalid repay request fields", err)
		}
		req := proto.RepayReq{ContractID: cid, ReqNonce: *reqNonce, Close: reqMsg.Close}
		reqSign := proto.RepayReqSignBytes(req, ephPub, sealed)
		if !crypto.Verify(c.IOU.Debtor, crypto.SHA3_256(reqSign), sigB) {
			die("invalid sigb", fmt.Errorf("debtor signature check failed"))
		}

		ack := proto.Ack{
			ContractID: cid,
			ReqNonce:   *reqNonce,
			Decision:   uint8(*decision),
			Close:      *decision == 1,
		}
		ackPayload, err := proto.EncodeAckPayload(*idHex, ack.Decision, ack.Close)
		if err != nil {
			die("encode ack payload failed", err)
		}
		ackEph, ackSealed, err := e2eSeal(proto.MsgTypeAck, cid, *reqNonce, c.IOU.Debtor, ackPayload)
		if err != nil {
			die("e2e seal failed", err)
		}
		ack.EphemeralPub = ackEph
		ack.Sealed = ackSealed

		// v0.0.2: sign over SHA3_256(message)
		ackSign := proto.AckSignBytes(cid, ack.Decision, ack.Close, ackEph, ackSealed)
		sigA := crypto.Sign(privA, crypto.SHA3_256(ackSign))

		if *decision == 1 {
			if err := st.MarkClosed(cid, *forget); err != nil {
				die("mark closed failed", err)
			}
		}
		if err := st.AddAck(ack, sigA); err != nil {
			die("store ack failed", err)
		}

		if *outPath != "" {
			msg := proto.AckMsgFromAck(ack, sigA)
			data, err := proto.EncodeAckMsg(msg)
			if err != nil {
				die("encode message failed", err)
			}
			if err := writeMsg(*outPath, data); err != nil {
				die("write message failed", err)
			}
			return
		}

		fmt.Println("ACK sigA:", hex.EncodeToString(sigA))
		if *decision == 1 {
			fmt.Println("CLOSED", *idHex)
		} else {
			fmt.Println("REJECTED", *idHex)
		}

	case "recv":
		fs := flag.NewFlagSet("recv", flag.ExitOnError)
		inPath := fs.String("in", "", "message file path")
		_ = fs.Parse(os.Args[2:])

		if *inPath == "" {
			die("missing --in", fmt.Errorf("path required"))
		}
		data, err := os.ReadFile(*inPath)
		if err != nil {
			die("read message failed", err)
		}
		payload, err := proto.ReadFrame(bytes.NewReader(data))
		if err == nil {
			recvData(payload, st)
			return
		}
		recvData(data, st)

	case "quic-listen":
		fs := flag.NewFlagSet("quic-listen", flag.ExitOnError)
		addr := fs.String("addr", "", "listen addr (host:port)")
		_ = fs.Bool("insecure", false, "skip certificate verification (client only)")
		_ = fs.Parse(os.Args[2:])
		if *addr == "" {
			die("missing --addr", fmt.Errorf("address required"))
		}
		fmt.Println("QUIC LISTEN", *addr)
		if err := network.ListenAndServe(*addr, func(data []byte) {
			recvData(data, st)
		}); err != nil {
			die("quic listen failed", err)
		}

	case "quic-send":
		fs := flag.NewFlagSet("quic-send", flag.ExitOnError)
		addr := fs.String("addr", "", "server addr (host:port)")
		inPath := fs.String("in", "", "message file path")
		insecure := fs.Bool("insecure", false, "skip certificate verification")
		_ = fs.Parse(os.Args[2:])
		if *addr == "" {
			die("missing --addr", fmt.Errorf("address required"))
		}
		if *inPath == "" {
			die("missing --in", fmt.Errorf("path required"))
		}
		data, err := os.ReadFile(*inPath)
		if err != nil {
			die("read message failed", err)
		}
		if err := network.Send(*addr, data, *insecure); err != nil {
			die("quic send failed", err)
		}

	default:
		fmt.Println("unknown command")
		os.Exit(1)
	}
}
