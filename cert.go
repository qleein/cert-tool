package main

import (
    "log"
    "bytes"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "encoding/base64"
    "syscall/js"
    "crypto/rsa"
    "crypto/rand"
    "math/big"
    "time"

    "github.com/pavel-v-chernykh/keystore-go"
)

var (
    ch = make(chan struct{}, 0)
)

func der2pem(args []js.Value) {
    input := args[0]
    ty := args[1].String()
    buf := make([]byte, input.Length())
    for i := 0; i < input.Length(); i++ {
        buf[i] = byte(input.Index(i).Int())
    }

    if ty == "cert" {
        b := &pem.Block{
            Type: "CERTIFICATE",
            Bytes: buf,
        }
        pemCert := pem.EncodeToMemory(b)
        pemCertString := base64.StdEncoding.EncodeToString([]byte(pemCert))
        pemCertUrl := "data:application/octet-stream;charset=UTF-8;base64," + pemCertString
        js.Global().Get("document").Call("getElementById", "certificate-pem").Set("textContent", string(pemCert))
        js.Global().Get("document").Call("getElementById", "certificate-download").Call("setAttribute", "href", pemCertUrl);   
    } else if ty == "pkey" {
        b := &pem.Block{
            Type: "PRIVATE KEY",
            Bytes: buf,
        }
        pemPkey := pem.EncodeToMemory(b)
        pemPkeyString := base64.StdEncoding.EncodeToString([]byte(pemPkey))
        pemPkeyUrl := "data:application/octet-stream;charset=UTF-8;base64," + pemPkeyString
        js.Global().Get("document").Call("getElementById", "private-key-pem").Set("textContent", string(pemPkey))
        js.Global().Get("document").Call("getElementById", "private-key-download").Call("setAttribute", "href", pemPkeyUrl);         
    }
}

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

func newCert(args[] js.Value) (derCert, derPriv []byte){
    log.Println("len: ", len(args))
    jsPKey := args[0]
    buf := make([]byte, jsPKey.Length())
    for i := 0; i < jsPKey.Length(); i++ {
        buf[i] = byte(jsPKey.Index(i).Int())
    }
    key, err := x509.ParsePKCS8PrivateKey(buf)
    if err != nil {
        log.Fatal(err)
    }
    priv, ok := key.(*rsa.PrivateKey)
    if !ok {
        log.Fatal("only RSA privatekey is supported")
    }

    certinfo := args[1]

    names := pkix.Name{}
    subject := certinfo.Get("subject")
    if subject != js.Undefined() {
        if subject.Get("commonName") != js.Undefined() {
            names.CommonName= subject.Get("commonName").String();
        }
        if subject.Get("organizationName") != js.Undefined() {
            names.Organization = []string{subject.Get("organizationName").String()};
        }
        if subject.Get("organizationUnitName") != js.Undefined() {
            names.OrganizationalUnit = []string{subject.Get("organizationUnitName").String()};
        }
        if subject.Get("countryCode") != js.Undefined() {
            names.Country = []string{subject.Get("countryCode").String()};
        }
        if subject.Get("stasteOrProvinceName") != js.Undefined() {
            names.Province = []string{subject.Get("stasteOrProvinceName").String()};
        }
        if subject.Get("localityName") != js.Undefined() {
            names.Locality = []string{subject.Get("localityName").String()};
        }
    }

    days := 365
    if certinfo.Get("expiryDate") != js.Undefined() {
        days = certinfo.Get("expiryData").Int()
    }

    isCA := false
    if certinfo.Get("isCA") != js.Undefined() {
        isCA = certinfo.Get("isCA").Bool()
    }

    template := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().Unix()),
        Subject: names,
        NotBefore: time.Now(),
        NotAfter: time.Now().AddDate(0, 0, days),
        KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        BasicConstraintsValid: true,
        IsCA: isCA,
    }

    cacert := template
    capriv := priv
    if len(args) >= 3 {
        cainfo := args[2]
        pemCACert := cainfo.Get("cert").String()
        pemCAPkey := cainfo.Get("pkey").String()
        var b *pem.Block
        var err error
        b, _ = pem.Decode([]byte(pemCACert))
        cacert, err = x509.ParseCertificate(b.Bytes)
        if err != nil {
            log.Fatal(err)
        }
        b, _ = pem.Decode([]byte(pemCAPkey))
        pkeyinterface, err := x509.ParsePKCS8PrivateKey(b.Bytes)
        if err != nil {
            log.Fatal(err)
        }
        capriv = pkeyinterface.(*rsa.PrivateKey)
    }

    template.DNSNames = append(template.DNSNames, "test.org")
    derBytes, err := x509.CreateCertificate(rand.Reader, template, cacert, &priv.PublicKey, capriv)
    if err != nil {
        log.Fatal(err)
    }

    return derBytes, buf
}

func createCACertificate(args []js.Value) {
    derCert, derPriv := newCert(args)

    pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
    pemCertString := base64.StdEncoding.EncodeToString([]byte(pemCert))
    pemCertUrl := "data:application/octet-stream;charset=UTF-8;base64," + pemCertString
    js.Global().Get("document").Call("getElementById", "ca-cert-pem").Set("textContent", string(pemCert))
    js.Global().Get("document").Call("getElementById", "ca-certificate-download").Call("setAttribute", "href", pemCertUrl);

    pemPkey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes:derPriv})
    pemPkeyString := base64.StdEncoding.EncodeToString([]byte(pemPkey))
    pemPkeyUrl := "data:application/octet-stream;charset=UTF-8;base64," + pemPkeyString
    js.Global().Get("document").Call("getElementById", "ca-private-key-pem").Set("textContent", string(pemPkey))
    js.Global().Get("document").Call("getElementById", "ca-private-key-download").Call("setAttribute", "href", pemPkeyUrl)

}

func createCertificate(args[] js.Value) {
    derCert, derPriv := newCert(args)

    pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
    pemCertString := base64.StdEncoding.EncodeToString([]byte(pemCert))
    pemCertUrl := "data:application/octet-stream;charset=UTF-8;base64," + pemCertString
    js.Global().Get("document").Call("getElementById", "certificate-pem").Set("textContent", string(pemCert))
    js.Global().Get("document").Call("getElementById", "certificate-download").Call("setAttribute", "href", pemCertUrl);

    pemPkey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes:derPriv})
    pemPkeyString := base64.StdEncoding.EncodeToString([]byte(pemPkey))
    pemPkeyUrl := "data:application/octet-stream;charset=UTF-8;base64," + pemPkeyString
    js.Global().Get("document").Call("getElementById", "private-key-pem").Set("textContent", string(pemPkey))
    js.Global().Get("document").Call("getElementById", "private-key-download").Call("setAttribute", "href", pemPkeyUrl)
}


func main() {

    js.Global().Set("wasmJKS2Pem", js.NewCallback(jks2pem))
    js.Global().Set("wasmDer2Pem", js.NewCallback(der2pem))
    js.Global().Set("wasmCreateCertificate", js.NewCallback(createCertificate))
    js.Global().Set("wasmCreateCACertificate", js.NewCallback(createCACertificate))
    <-ch
    log.Println("end")
}
