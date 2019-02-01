package main

import (
    "log"
    "crypto/x509"
    "encoding/pem"
    "syscall/js"
    "bytes"

    "github.com/pavel-v-chernykh/keystore-go"
)

var (
    ch = make(chan struct{}, 0)
)

func jks2pem(args []js.Value) {
    input := args[0]
    passwd := args[1].String()

    buf := make([]byte, input.Length())
    for i := 0; i < input.Length(); i++ {
        buf[i] = byte(input.Index(i).Int())
    }

    reader := bytes.NewReader(buf)
    ks, err := keystore.Decode(reader, []byte(passwd))
    if err != nil {
        log.Fatal(err)
    }

    for _, v := range ks {
        val, ok := v.(*keystore.PrivateKeyEntry)
        if ok {
            
            certchain := ""
            for _, cert := range val.CertChain {
                _,  err := x509.ParseCertificate(cert.Content)
                if err != nil {
                    log.Fatal(err)
                }

                block := &pem.Block{
                    Type: "CERTIFICATE",
                    Bytes: val.CertChain[0].Content,
                }

                certchain = certchain + "\n" + string(pem.EncodeToMemory(block))
            }

            block := &pem.Block {
                Type: "PRIVATE KEY",
                Bytes: val.PrivKey,
            }
            pkey := string(pem.EncodeToMemory(block))
            js.Global().Get("document").Call("getElementById", "certificate-pem").Set("textContent", certchain)
            js.Global().Get("document").Call("getElementById", "private-key-pem").Set("textContent", pkey)
            return
        }else {
            log.Fatal("unsupported keystore entry")
        }
    }

    return
}


func main() {

    var cb js.Callback
    cb = js.NewCallback(jks2pem)
    js.Global().Set("jks2pem", cb)
    log.Println("end")
    <-ch
    log.Println("end2")
/*
    raw := js.Global().Get("rawJKS")
    var buf = make([]byte, 0)
    for i := 0; i < raw.Length(); i++ {
        buf = append(buf, byte(raw.Index(i).Int()))
    }

    reader := bytes.NewReader(buf)
    password := js.Global().Get("JKSPassword").String()
    ks, err := keystore.Decode(reader, []byte(password))
    if err != nil {
        log.Fatal(err)
    }

    for _, v := range ks {
        val, ok := v.(*keystore.PrivateKeyEntry)
        if ok {
            cert, err := x509.ParseCertificate(val.CertChain[0].Content)
            if err != nil {
                log.Fatal(err)
            }

            m := map[string]string{}
            block := &pem.Block{
                Type: "CERTIFICATE",
                Bytes: cert.Raw,
            }

            m["cert"] = string(pem.EncodeToMemory(block))

            block = &pem.Block {
                Type: "PRIVATE KEY",
                Bytes: val.PrivKey,
            }
            m["privkey"] = string(pem.EncodeToMemory(block))
            js.Global().Get("window").Set("certFromJKS", m["cert"])
            js.Global().Get("window").Set("privkeyFromJKS", m["privkey"])
            return
        }else {
            log.Fatal("unsupported keystore entry")
        }
    }
*/

}
