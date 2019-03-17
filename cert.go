package main

import (
    "log"
    "bytes"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "syscall/js"
    "crypto/rsa"
    "crypto/rand"
    "math/big"
    "time"
    "net"

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
        args[2].Invoke(string(pemCert))
     } else if ty == "pkey" {
        b := &pem.Block{
            Type: "PRIVATE KEY",
            Bytes: buf,
        }
        pemPkey := pem.EncodeToMemory(b)
        args[2].Invoke(js.Undefined(), string(pemPkey))
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
            args[2].Invoke(certchain, pkey)
            return
        }else {
            log.Fatal("unsupported keystore entry")
        }
    }

    return
}

func newCert(args[] js.Value) (derCert, derPriv []byte){
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
    stime := time.Now()
    etime := time.Now().AddDate(0, 0, days)
    timefmt := "2006-01-02 15:04:05"
    if certinfo.Get("not before") != js.Undefined() {
        if stime, err = time.Parse(timefmt,certinfo.Get("not before").String()); err != nil {
            log.Fatal(err)
        }
    }
    if certinfo.Get("not after") != js.Undefined() {
        if etime, err = time.Parse(timefmt, certinfo.Get("not after").String()); err != nil {
            log.Fatal(err)
        }
    }

    isCA := false
    if certinfo.Get("isCA") != js.Undefined() {
        isCA = certinfo.Get("isCA").Bool()
    }

    template := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().Unix()),
        Subject: names,
        NotBefore: stime,
        NotAfter: etime,
        KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        BasicConstraintsValid: true,
        IsCA: isCA,
    }

    cacert := template
    capriv := priv
    if len(args) >= 3 && args[2] != js.Undefined() {
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

    altnames := certinfo.Get("subject-alt-name")
    if altnames != js.Undefined() {
        for i := 0; i < altnames.Length(); i++ {
            v := altnames.Index(i).String()
            if net.ParseIP(v) != nil {
                template.IPAddresses = append(template.IPAddresses, net.ParseIP(v))
            } else {
                template.DNSNames = append(template.DNSNames, v)
            }
        }
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, template, cacert, &priv.PublicKey, capriv)
    if err != nil {
        log.Fatal(err)
    }

    return derBytes, buf
}

func createCACertificate(args []js.Value) {
    n := len(args)
    if n != 3 {
        log.Fatal("invalid arguments")
    }

    derCert, derPriv := newCert(args[0:2])
    pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
    pemPkey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes:derPriv})
    args[2].Invoke(string(pemCert), string(pemPkey))
    return
}

func createCertificate(args[] js.Value) {
    n := len(args)
    if n != 4 {
        log.Fatal("invalid arguments")
    }

    cb := args[n-1]
    derCert, derPriv := newCert(args[0:n-1])
    pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
    pemPkey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes:derPriv})
    cb.Invoke(string(pemCert), string(pemPkey))
    return
}


func main() {

    js.Global().Set("wasmJKS2Pem", js.NewCallback(jks2pem))
    js.Global().Set("wasmDer2Pem", js.NewCallback(der2pem))
    js.Global().Set("wasmCreateCertificate", js.NewCallback(createCertificate))
    js.Global().Set("wasmCreateCACertificate", js.NewCallback(createCACertificate))
    <-ch
    log.Println("end")
}
