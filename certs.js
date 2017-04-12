var CACertType = "self-signed";
var CACertificateInfo = {
    type: "self-signed",
    upload: {},
    created: {},
};


document.addEventListener("DOMContentLoaded", function() {
    "use strict";

    // Fix Apple prefix if needed
    if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle) {
        window.crypto.subtle = window.crypto.webkitSubtle;  // Won't work if subtle already exists
    }

    // Check that web crypto is even available
    if (!window.crypto || !window.crypto.subtle) {
        alert("Your browser does not support the Web Cryptography API! This page will not work.");
        return;
    }
});


function checkCACertificate() {
    var ty = CACertificateInfo.type;
    if (ty == "self-signed") {
        return true;
    }

    if (ty == "upload") {
        return CACertificateInfo.upload;
    }

    if (ty == "created") {
        return CACertificateInfo.created;
    }

    return false;
}


function handleWhereIsCA(evt) {
    var radio = document.getElementsByName("whereisca");
    document.getElementById("self-signed").style.display = "none";
    document.getElementById("upload-ca").style.display = "none";
    document.getElementById("create-ca").style.display = "none";

    for (var i = 0; i < radio.length; i++) {
        if (!radio[i].checked) {
            continue;
        }

        var elem;
        if (radio[i].value == "upload") {
            elem = document.getElementById("upload-ca");
            elem.style.display = "block";
            CACertificateInfo.type = "upload";
        } else if (radio[i].value == "new"){
            elem = document.getElementById("create-ca");
            elem.style.display = "block";
            CACertificateInfo.type = "create";
        } else {
            CACertificateInfo.type = "self-signed";
            elem = document.getElementById("self-signed");
            elem.style.display = "block";
        }
    }
}


function handleFileCACert(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;
    tempReader.onload =
        function(event)
        {
            var buf = pemToDer(event.target.result, "certificate");
            const asn1 = org.pkijs.fromBER(buf);
            const certificate = new org.pkijs.simpl.CERT({schema:asn1.result});
            //document.write(JSON.stringify(certificate.subject.toJSON()));
            var names = extract_entity(certificate.subject);
            /*
            var text = "";
            text = text + "Common Name: " + names["commonName"] + "\n";
                text = text + "Organization Name: " + names["organizationName"] + "\n";
            text = text + "Organizational Unit Name: " + names["organizationUnitName"] + "\n";
            text = text + "Country Name: " + names["countryCode"] + "\n";
            text = text + "State or Province Name: " + names["stateOrProvinceName"] + "\n";
            text = text + "Locality Name : " + names["localityName"] + "\n";
            document.getElementById("ca-cert-pem").textContent = text;
            //document.write(JSON.stringify(subj));
            */
            CACertificateInfo.upload.cert = certificate;
            CACertificateInfo.upload.subject = names;
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}



function handleFileCAPrivateKey(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;

    tempReader.onload =
        function(event)
        {
            var buf = pemToDer(event.target.result, "privatekey");
            const asn1 = org.pkijs.fromBER(buf);
            //const privatekey = new org.pkijs.simpl.PKCS8({schema:asn1.result});
            //const privatekey = new org.pkijs.simpl.x509.RSAPrivateKey({schema:asn1.result});
            //const privatekey = window.crypto.subtle.importKey("raw", buf, "RSASSA-PKCS1-v1_5", true, ["sign"]);
            window.crypto.subtle.importKey(
                "pkcs8",
                buf,
                { name: "RSASSA-PKCS1-v1_5",
                  hash: {name:"SHA-256"}
                },
                true,
                ["sign"]
            ).
            then(function(privatekey) {
                CACertificateInfo.upload.privateKey = privatekey;
                window.crypto.subtle.exportKey('pkcs8', privatekey).
                then(function(spki) {
                    var pemPublicKey = convertBinaryToPem(spki, "PRIVATE KEY");
                    var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemPublicKey);
                    //document.getElementById("ca-private-key-pem").textContent = pemPublicKey;
                    //document.getElementById("ca-private-key-download").setAttribute("href", pemUrl);
                })
            }) .
            catch(function(err) {
                console.log("Error parse privatekey: " + err.message);
            });

            console.log("OK END");
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}


function createCACert() {
    var commonName        = document.getElementById("ca-common-name").value;
    var organization      = document.getElementById("ca-organization").value;
    var organizationUnit  = document.getElementById("ca-organization-unit").value;
    var countryCode       = document.getElementById("ca-country-code").value;
    var stateName         = document.getElementById("ca-state-name").value;
    var localityName      = document.getElementById("ca-locality-name").value;

    countryCode = countryCode.toUpperCase();
    var names = {
        commonName:commonName,
        countryCode:countryCode,
        stasteOrProvinceName:stateName,
        localityName: localityName,
        organizationName: organization,
        organizationUnitName: organizationUnit,
    }
    console.log("ca names:", names);

    var keyPair;
    window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: {name: "SHA-256"}
        },
        true,   // Must extract private key to create PEM files later
        ["sign", "verify"]
    ).
    then(function(newKeyPair) {
        keyPair = newKeyPair;
        return buildCACertificateObject(names, keyPair);
    }) .
    then(function(cert) {
        CACertificateInfo = {
            type: "created",
            subject: names,
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
        }

        var pemCert = convertBinaryToPem(cert.toSchema(true).toBER(false), "CERTIFICATE");
        var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemCert);
        document.getElementById("ca-cert-pem").textContent = pemCert;
        document.getElementById("ca-certificate-download").setAttribute("href", pemUrl);

        window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey).
        then(function(pkcs8) {
            var pemPrivateKey = convertBinaryToPem(pkcs8, "PRIVATE KEY");
            var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemPrivateKey);
            document.getElementById("ca-private-key-pem").textContent = pemPrivateKey;
            document.getElementById("ca-private-key-download").setAttribute("href", pemUrl);
        });
     }) .
    catch(function(err) {
        console.log("Error creating certificate: " + err.message);
    });
}



function createCert() {
    var keyPair;
    var commonName       = document.getElementById("common-name").value;
    var organization     = document.getElementById("organization").value;
    var organizationUnit = document.getElementById("organization-unit").value;
    var countryCode      = document.getElementById("country-code").value;
    var stateName        = document.getElementById("state-name").value;
    var localityName     = document.getElementById("locality-name").value;

    //if (!commonName) {alert("You must enter a name for the certificate."); return;}
    //if (countryCode.length !== 2) {alert("Country codes must be two characters long."); return;}
    countryCode = countryCode.toUpperCase();

    var names = {
        commonName:commonName,
        countryCode:countryCode,
        stasteOrProvinceName:stateName,
        localityName: localityName,
        organizationName: organization,
        organizationUnitName: organizationUnit,
    }

    var CACert = checkCACertificate();
    if (!CACert) {
        console.log("Not ca certificate defined");
        return;
    }

    window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),  // 24 bit representation of 65537
            hash: {name: "SHA-256"}
        },
        true,   // Must extract private key to create PEM files later
        ["sign", "verify"]
    ).
    then(function(newKeyPair) {
        keyPair = newKeyPair;
        if (CACert.subject && CACert.privateKey) {
            return buildCertificateObject(names, keyPair, CACert.subject, CACert.privateKey);
        } else
            return buildCertificateObject(names, keyPair, names, keyPair.privateKey);
    }) .
    then(function(cert) {
        var pemCert = convertBinaryToPem(cert.toSchema(true).toBER(false), "CERTIFICATE");
        var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemCert);
        document.getElementById("certificate-pem").textContent = pemCert;
        document.getElementById("certificate-download").setAttribute("href", pemUrl);

        window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey).
        then(function(pkcs8) {
            var pemPrivateKey = convertBinaryToPem(pkcs8, "PRIVATE KEY");
            var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemPrivateKey);
            document.getElementById("private-key-pem").textContent = pemPrivateKey;
            document.getElementById("private-key-download").setAttribute("href", pemUrl);
        });
    }).
    catch(function(err) {
        alert("Error creating certificate: " + err.message);
    });
};


function buildCACertificateObject(names, keyPair) {
    var cert = new org.pkijs.simpl.CERT();

    cert.version = 2;
    setSerialNumber(cert, Date.now());
    setEntity2(cert.subject, names);
    setEntity2(cert.issuer, names);
    setValidityPeriod(cert, new Date(), 3650);
    setEmptyExtensions(cert);
    setCABit(cert, true, 2);
    //setKeyUsage(cert, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign)
    setKeyUsage(cert, true, true, true, false, false, false, false);

    setSignatureAlgorithm(cert, "1.2.840.113549.1.1.11");
    return setPublicKey(cert, keyPair.publicKey).
        then(function() {return signCert(cert, "1.2.840.113549.1.1.11", keyPair.privateKey)}).
        then(function() {return cert});
}


// Returns a Promise yielding the certificate object
function buildCertificateObject(subject, keyPair, issuer, issuerPrivateKey) {
    var cert = new org.pkijs.simpl.CERT();

    cert.version = 2;
    setSerialNumber(cert, Date.now());
    setEntity2(cert.subject, subject);
    setEntity2(cert.issuer, issuer)

    setValidityPeriod(cert, new Date(), 365);  // Good from today for 730 days
    setEmptyExtensions(cert);
    //setAltName(cert);
    setCABit(cert, false);
    //setKeyUsage(cert, true, true, true, false, false, false, false); // digitalSignature, nonRepudiation, keyCertSign, cRLSign
    //setExtendKeyUsage(cert);
    setSignatureAlgorithm(cert, "1.2.840.113549.1.1.11"); // RSA with SHA-256

    return setPublicKey(cert, keyPair.publicKey).
        then(function() {return signCert(cert, "1.2.840.113549.1.1.11", issuerPrivateKey)}).
        then(function() {return cert});
}
// Helper functions

function setSerialNumber(cert, serialNumber) {
    cert.serialNumber = new org.pkijs.asn1.INTEGER({value: serialNumber});;
}

function setValidityPeriod(cert, startDate, durationInDays) {
    // Normalize to midnight
    var start = new Date(startDate);
    start.setHours(0);
    start.setMinutes(0);
    start.setSeconds(0);
    var end   = new Date(start.getTime() + durationInDays * 24 * 60 * 60 * 1000);

    cert.notBefore.value = start;
    cert.notAfter.value  = end;
}

function setEmptyExtensions(cert) {
    cert.extensions = new Array();
}

function setCABit(cert, isCA, pathlen) {
    var value = {
        cA: isCA,
    }

    if (isCA && pathlen) {
        value.pathLenConstraint = pathlen;
    }

    var basicConstraints = new org.pkijs.simpl.x509.BasicConstraints(value);
    cert.extensions.push(new org.pkijs.simpl.EXTENSION({
        extnID: "2.5.29.19",
        critical: false,
        extnValue: basicConstraints.toSchema().toBER(false),
        parsedValue: basicConstraints
    }));
}

function setKeyUsage(cert, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign) {
    var keyUsageBits = new ArrayBuffer(1);
    var keyUsageBytes = new Uint8Array(keyUsageBits);

    keyUsageBytes[0] = 0;
    if (digitalSignature)   {keyUsageBytes[0] |= 0x80;}
    if (nonRepudiation)     {keyUsageBytes[0] |= 0x40;}
    if (keyEncipherment)    {keyUsageBytes[0] |= 0x20;}
    if (dataEncipherment)   {keyUsageBytes[0] |= 0x10;}
    if (keyAgreement)       {keyUsageBytes[0] |= 0x08;}
    if (keyCertSign)        {keyUsageBytes[0] |= 0x04;}
    if (cRLSign)            {keyUsageBytes[0] |= 0x02;}

    var keyUsage = new org.pkijs.asn1.BITSTRING({value_hex: keyUsageBits});
    cert.extensions.push(new org.pkijs.simpl.EXTENSION({
        extnID: "2.5.29.15",
        critical: true,
        extnValue: keyUsage.toBER(false),
        parsedValue: keyUsage
    }));
}

function setAltName(cert) {
    var extKeyUsage = new org.pkijs.simpl.x509.AltName({
        altNames: [ new org.pkijs.simpl.GENERAL_NAME({value: "test.com"})]
    })

    var altNames = new org.pkijs.simpl.GENERAL_NAMES({
        names: [
            new org.pkijs.simpl.GENERAL_NAME({
                NameType: 2,
                Name: "test.com"
            })
        ]
    })
    cert.extensions.push(new org.pkijs.simpl.EXTENSION({
        extnID: "2.5.29.17",
        extnValue: altNames.toSchema().toBER(false),
    }));

    return;
}


function setSignatureAlgorithm(cert, oid) {
    cert.signatureAlgorithm.algorithm_id = oid; // In tbsCert
}

function setPublicKey(cert, publicKey) {
    return cert.subjectPublicKeyInfo.importKey(publicKey);
}

function signCert(cert, oid, privateKey) {
    cert.signature.algorithm_id = oid; // In actual signature
    return cert.sign(privateKey);
    //return cert.sign(CAPrivateKey);
}


// General helper functions

function arrayBufferToBase64String(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer)
    var byteString = '';

    for (var i=0; i<byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i]);
    }

    return btoa(byteString);
}



function convertBinaryToPem(binaryData, label) {

    var base64Cert = arrayBufferToBase64String(binaryData);

    var pemCert = "-----BEGIN " + label + "-----\r\n";

    var nextIndex = 0;
    var lineLength;
    while (nextIndex < base64Cert.length) {
        if (nextIndex + 64 <= base64Cert.length) {
            pemCert += base64Cert.substr(nextIndex, 64) + "\r\n";
        } else {
            pemCert += base64Cert.substr(nextIndex) + "\r\n";
        }
        nextIndex += 64;
    }

    pemCert += "-----END " + label + "-----\r\n";
    return pemCert;
}

function pemToDer(pem, label) {
    var pemString = String.fromCharCode.apply(null, new Uint8Array(pem));
	var isOpensslPrivateKey = false;

    if (label == "certificate") {
        var res = pemString.match(/-----BEGIN CERTIFICATE-----([a-zA-Z0-9+/=\n]*?)-----END CERTIFICATE-----/m);
        pemString = res[1]
    } else if (label == "privatekey") {
        var res = pemString.match(/-----BEGIN RSA PRIVATE KEY-----([a-zA-Z0-9+/=\n]*?)-----END RSA PRIVATE KEY-----/m);
        if (res) {
            isOpensslPrivateKey = true;
            pemString = res[1];
        } else {
            res = pemString.match(/-----BEGIN PRIVATE KEY-----([a-zA-Z0-9+/=\n]*?)-----END PRIVATE KEY-----/m);
            pemString = res[1];
        }
    }

    // base64 decode
	pemString = pemString.replace(/\n/g, "");
    var derString = atob(pemString);

    // String to ArrayBuffer

    var buf = new ArrayBuffer(derString.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen=derString.length; i < strLen; i++) {
        bufView[i] = derString.charCodeAt(i);
    }

    if (!isOpensslPrivateKey) {
        return buf;
    }
    
    // Convert openssl format privatekey to pkcs#8 format
    var pkcs8 = new org.pkijs.simpl.PKCS8();
    pkcs8.version = 0;
    pkcs8.privateKeyAlgorithm = new org.pkijs.simpl.ALGORITHM_IDENTIFIER({algorithm_id:"1.2.840.113549.1.1.1", algorithm_params: new org.pkijs.asn1.NULL()})
    pkcs8.privateKey = new org.pkijs.asn1.OCTETSTRING({value_hex:buf});
    var buf2 = pkcs8.toSchema(true).toBER(false);
    return buf2
}

function extract_entity(entity) {
    var subj = entity.toJSON();
    var names = {
        commonName          : "",
        organizationName    : "",
        organizationUnitName : "",
        countryCode         : "",
        stateOrProvinceName : "",
        localityName        : ""
    };
    for (var i = 0; i < subj["types_and_values"].length; i++) {
        var ty = subj["types_and_values"][i]["type"];
        var val = subj["types_and_values"][i]["value"]["value_block"]["value"];
        switch (ty) {
        case "2.5.4.3":
            names["commonName"] = val;
            break;
        case "2.5.4.6":
            names["countryCode"] = val;
            break;
        case "2.5.4.7":
            names["localityName"] = val;
            break;
        case "2.5.4.8":
            names["stateOrProvinceName"] = val;
            break;
        case "2.5.4.10":
            names["organizationName"] = val;
            break;
        case "2.5.4.11":
            names["organizationUnitName"] = val;
            break;
        default:
            break;
        }
    }

    return names;
}


function setEntity2(entity, names) {
    if (names["commonName"]) {
       entity.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3",
            value: new org.pkijs.asn1.UTF8STRING({value: names["commonName"]})
        }));
    }
    if (names["countryCode"]) {
       entity.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6",
            value: new org.pkijs.asn1.PRINTABLESTRING({value: names["countryCode"]})
        }));
    }
    if (names["stateOrProvinceName"]) {
       entity.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.8",
            value: new org.pkijs.asn1.UTF8STRING({value: names["stateOrProvinceName"]})
        }));
    }
    if (names["localityName"]) {
       entity.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.7",
            value: new org.pkijs.asn1.UTF8STRING({value: names["localityName"]})
        }));
    }
    if (names["organizationName"]) {
       entity.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.10",
            value: new org.pkijs.asn1.UTF8STRING({value: names["organizationName"]})
        }));
    }
    if (names["organizationUnitName"]) {
       entity.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.11",
            value: new org.pkijs.asn1.UTF8STRING({value: names["organizationUnitName"]})
        }));
    }
}
