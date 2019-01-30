package main

import (
    "log"
    "crypto/x509"
    "encoding/pem"
    "syscall/js"
    "bytes"

    "github.com/pavel-v-chernykh/keystore-go"
)


func main() {
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


}
