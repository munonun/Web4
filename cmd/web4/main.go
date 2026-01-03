// cmd/web4/main.go
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"web4mvp/internal/crypto"
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: web4 <keygen|open|list|close|ack>")
		os.Exit(1)
	}

	root := homeDir()
	_ = os.MkdirAll(root, 0700)

	st := store.New(filepath.Join(root, "contracts.jsonl"), filepath.Join(root, "acks.jsonl"))

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

		// v0.0.2: sign over SHA3_256(message)
		iouMsg := proto.IOUBytes(iou)
		sigB := crypto.Sign(priv, crypto.SHA3_256(iouMsg))

		// NOTE: in real life creditor also signs; for MVP we allow "half-open" then later attach creditor sig.
		c := proto.Contract{
			IOU:     iou,
			SigCred: nil,
			SigDebt: sigB,
			Status:  "OPEN",
		}
		if err := st.AddContract(c); err != nil {
			die("store failed", err)
		}
		id := proto.ContractID(iou)
		fmt.Println("OPEN", hex.EncodeToString(id[:]))

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

		req := proto.RepayReq{ContractID: cid, ReqNonce: *reqNonce, Close: true}

		// v0.0.2: sign over SHA3_256(message)
		reqMsg := proto.RepayReqBytes(req)
		sig := crypto.Sign(priv, crypto.SHA3_256(reqMsg))

		_ = pub // (debtor pub already in key file)

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
		_ = fs.Parse(os.Args[2:])

		_, privA, err := crypto.LoadKeypair(root)
		if err != nil {
			die("load keys failed", err)
		}
		idBytes, err := hex.DecodeString(*idHex)
		if err != nil || len(idBytes) != 32 {
			die("invalid --id", fmt.Errorf("need 32 bytes hex"))
		}
		var cid [32]byte
		copy(cid[:], idBytes)

		sigB, err := hex.DecodeString(*sigBHex)
		if err != nil {
			die("invalid sigb", err)
		}

		// For MVP we don't verify sigB against debtor pub (we can add once we bind both pubs + sigs).
		_ = sigB

		ack := proto.Ack{ContractID: cid, ReqNonce: *reqNonce, Decision: uint8(*decision), Close: true}

		// v0.0.2: sign over SHA3_256(message)
		ackMsg := proto.AckBytes(ack)
		sigA := crypto.Sign(privA, crypto.SHA3_256(ackMsg))

		if *decision == 1 {
			if err := st.MarkClosed(cid, *forget); err != nil {
				die("mark closed failed", err)
			}
		}
		if err := st.AddAck(ack, sigA); err != nil {
			die("store ack failed", err)
		}

		fmt.Println("ACK sigA:", hex.EncodeToString(sigA))
		if *decision == 1 {
			fmt.Println("CLOSED", *idHex)
		} else {
			fmt.Println("REJECTED", *idHex)
		}

	default:
		fmt.Println("unknown command")
		os.Exit(1)
	}
}
