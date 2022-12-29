package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"io/ioutil"
	"os"
)

var (
	file       = flag.String("file", "", "The encrypted private key file you support")
	passwd     = flag.String("passwd", "", "The password of encrypted private key file you support")
	prikey_str = flag.String("prikey", "", "Your need be encrypted private key string")
)

const (
	veryLightScryptN = 2
	veryLightScryptP = 1
)

func init() {
	flag.Parse()
}

func main() {
	if *prikey_str != "" && *file != "" {
		flag.Usage()
		panic("private key and keystore both input!!!")
	} else if *prikey_str == "" && *file == ""{
		flag.Usage()
		panic("private key and keystore both not input!!!")
	} else if *prikey_str !=  "" && *passwd !=  "" {
		var prikey_bytes []byte
		var err error
		if (*prikey_str)[:2] != "0x" {
			*prikey_str = "0x" + *prikey_str
		}

		prikey_bytes, err = hexutil.Decode(*prikey_str)
		if err != nil {
			panic(fmt.Sprintf("string hex decode err: %v", err))
		}

		prikey, err := crypto.ToECDSA(prikey_bytes)
		if err != nil {
			panic(fmt.Sprintf("crypto to ecdsa err: %v", err))
		}
		addr := crypto.PubkeyToAddress(prikey.PublicKey)
		id, err := uuid.NewRandom()
		if err != nil {
			panic(fmt.Sprintf("could not create random uuid: %v", err))
		}
		pk := &keystore.Key{
			Id:         id,
			Address:    addr,
			PrivateKey: prikey,
		}
		encryptkey_bytes, err := keystore.EncryptKey(pk, *passwd, veryLightScryptN, veryLightScryptP)
		if err != nil {
			panic(fmt.Sprintf("private key encryptKey err: %v", err))
		}
		if _, err := os.Stat("./encryptstore.key"); os.IsExist(err) {
			panic(fmt.Sprintf("file is exist: %v", err))
		}
		if err := ioutil.WriteFile("./encryptstore.key", encryptkey_bytes, 0666); err != nil {
			panic(fmt.Sprintf("file write err: %v", err))
		}

		fmt.Println("encrypt successful, encryptstore store to ", "/encryptstore.key")
	} else if *file !=  "" && *passwd !=  "" {
		if _, err := os.Stat(*file); os.IsNotExist(err) {
			panic(fmt.Sprintf("file is not exist: %v", err))
		}

		keyjson, err := ioutil.ReadFile(*file)
		if err != nil {
			panic(fmt.Sprintf("file read err: %v", err))
		}

		key, err := keystore.DecryptKey(keyjson, *passwd)
		if err != nil {
			panic(fmt.Sprintf("keystore decryptKey err: %v", err))
		}
		prikey := hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))

		fmt.Println("decrypt successful, private key: ", prikey)
	} else {
		flag.Usage()
		panic("others input err!!!")
	}
}
