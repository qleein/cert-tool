import * as asn1js from "asn1js";
import Certificate from "pkijs/src/Certificate";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import Extension from "pkijs/src/Extension";
import RSAPublicKey from "pkijs/src/RSAPublicKey";
import RSAPrivateKey from "pkijs/src/RSAPrivateKey";
import CertificateChainValidationEngine from "pkijs/src/CertificateChainValidationEngine";
import CertificateRevocationList from "pkijs/src/CertificateRevocationList";
import { stringToArrayBuffer, bufferToHexCodes } from "pvutils";
import { getCrypto, getAlgorithmParameters, setEngine } from "pkijs/src/common";
import BasicConstraints from "pkijs/src/BasicConstraints";

import GeneralName from "pkijs/src/GeneralName";
import GeneralNames from "pkijs/src/GeneralNames";
//*********************************************************************************

let certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT
let privateKeyBuffer = new ArrayBuffer(0);
let hashAlg = "SHA-256";
let signAlg = "RSASSA-PKCS1-v1_5";

let CACertificateInfo = {
    type: "self-signed",
    upload: {},
    created: {},
};


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

function copyToClipboard(id) {
    var elem = document.getElementById(id);
    var text = elem.textContent;
    if (window.clipboardData && window.clipboardData.setData) {
        // IE specific code path to prevent textarea being shown while dialog is visible.
        return clipboardData.setData("Text", text); 

    } else if (document.queryCommandSupported && document.queryCommandSupported("copy")) {
        var textarea = document.createElement("textarea");
        textarea.textContent = text;
        textarea.style.position = "fixed";  // Prevent scrolling to bottom of page in MS Edge.
        document.body.appendChild(textarea);
        textarea.select();
        try {
            return document.execCommand("copy");  // Security exception may be thrown by some browsers.
        } catch (ex) {
            console.warn("Copy to clipboard failed.", ex);
            return false;
        } finally {
            document.body.removeChild(textarea);
        }
    }
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
            CACertificateInfo.type = "created";
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
            const asn1 = asn1js.fromBER(buf);
            const certificate = new Certificate({schema: asn1.result});
            //const certificate = new org.pkijs.simpl.CERT({schema:asn1.result});
            //document.write(JSON.stringify(certificate.subject.toJSON()));
            /*
            var names = extract_entity(certificate.subject);
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
            CACertificateInfo.upload.subject = certificate.subject;
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
            const asn1 = asn1js.fromBER(buf);
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

        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}

function setEntity(entity, names) {
    if (names["commonName"]) {
       entity.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.Utf8String({value: names["commonName"]})
        }));
    }
    if (names["countryCode"]) {
       entity.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6",
            value: new asn1js.PrintableString({value: names["countryCode"]})
        }));
    }
    if (names["stateOrProvinceName"]) {
       entity.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.8",
            value: new asn1js.Utf8String({value: names["stateOrProvinceName"]})
        }));
    }
    if (names["localityName"]) {
       entity.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.7",
            value: new asn1js.Utf8String({value: names["localityName"]})
        }));
    }
    if (names["organizationName"]) {
       entity.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.10",
            value: new asn1js.Utf8String({value: names["organizationName"]})
        }));
    }
    if (names["organizationUnitName"]) {
       entity.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.11",
            value: new asn1js.Utf8String({value: names["organizationUnitName"]})
        }));
    }
}

function formatPEM(pemString)
{
	/// <summary>Format string in order to have each line with length equal to 63</summary>
	/// <param name="pemString" type="String">String to format</param>

	const stringLength = pemString.length;
	let resultString = "";

	for(let i = 0, count = 0; i < stringLength; i++, count++)
	{
		if(count > 63)
		{
			resultString = `${resultString}\r\n`;
			count = 0;
		}

		resultString = `${resultString}${pemString[i]}`;
	}

	return resultString;
}

function createCertificateFinal(certificate, issuerPrivateKey, signAlg, hashAlg) {

	let publicKey;
	let privateKey;
    let signPrivateKey;

    const crypto = getCrypto();
    if (typeof crypto === "undefined")
        return Promise.reject("No WebCrypto extension found");
    //endregion

    let sequence = Promise.resolve();
	//region Create a new key pair
	sequence = sequence.then(() =>
	{
		//region Get default algorithm parameters for key generation
		const algorithm = getAlgorithmParameters(signAlg, "generatekey");
		if("hash" in algorithm.algorithm)
			algorithm.algorithm.hash.name = hashAlg;
		//endregion

		return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
	});
	//endregion

	//region Store new key in an interim variables
	sequence = sequence.then(keyPair =>
	{
		publicKey = keyPair.publicKey;
		privateKey = keyPair.privateKey;
	}, error => Promise.reject(`Error during key generation: ${error}`));
	//endregion

	//region Exporting public key into "subjectPublicKeyInfo" value of certificate
	sequence = sequence.then(() =>
		certificate.subjectPublicKeyInfo.importKey(publicKey)
	);
	//endregion

	//region Signing final certificate
	sequence = sequence.then(() =>
    {
        signPrivateKey = issuerPrivateKey || privateKey;
		return certificate.sign(signPrivateKey, hashAlg)
    }, error => Promise.reject(`Error during exporting public key: ${error}`));
	//endregion

	//region Encode and store certificate
	sequence = sequence.then(() =>
	{
		//trustedCertificates.push(certificate);
		certificateBuffer = certificate.toSchema(true).toBER(false);
	}, error => Promise.reject(`Error during signing: ${error}`));
	//endregion

    sequence = sequence.then(() =>
        crypto.exportKey("pkcs8", privateKey)
    );

    sequence = sequence.then(result =>
    {
        privateKeyBuffer = result;
        return {
            certificate: certificate,
            privateKey: privateKey
        };
    }, error => Promise.reject(`Error during exporting of private key: ${error}`));

    return sequence;
}


function createCACert()
{
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

    const certificate = new Certificate();

	certificate.version = 2;
    setSerialNumber(certificate, Date.now());
    setEntity(certificate.issuer, names)
    setEntity(certificate.subject, names);
    setValidityPeriod(certificate, new Date(), 3650);
	certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array
    setCABit(certificate, true, 2);
    setKeyUsage(certificate, false, false, false, false, false, true, false);

    var privateKey;
    const crypto = getCrypto();
    if (typeof crypto === "undefined")
        return Promise.reject("No WebCrypto extension found");

    return createCertificateFinal(certificate, null, "RSASSA-PKCS1-v1_5", "SHA-256").then(result =>
    {
        privateKey = result.privateKey;
        CACertificateInfo["created"].cert = certificate;
        CACertificateInfo["created"].subject = certificate.subject;
        CACertificateInfo["created"].privateKey = privateKey;
    }) .
    then(() =>
    {
        var pemCert = convertBinaryToPem(certificate.toSchema(true).toBER(false), "CERTIFICATE");
        document.getElementById("ca-cert-pem").textContent = pemCert;
        var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemCert);
        document.getElementById("ca-certificate-download").setAttribute("href", pemUrl);
    }) .
    then(() =>
    {
        crypto.exportKey("pkcs8", privateKey).
        then(pkcs8 =>
        {
            var pemPrivateKey = convertBinaryToPem(pkcs8, "PRIVATE KEY");
            document.getElementById("ca-private-key-pem").textContent = pemPrivateKey;
            var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemPrivateKey);
            document.getElementById("ca-private-key-download").setAttribute("href", pemUrl);
        });
    });
}


function getSubjectAltNames() {
    var elem = document.getElementById("subject-alt-name");
    var str = elem.value.toLowerCase();
    var strs = str.split(/[ ,]+/);

    return strs;
}

function createCert() {
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

    const certificate = new Certificate();
    let privateKey;
    const crypto = getCrypto();
    if (typeof crypto === "undefined")
        return Promise.reject("No WebCrypto extension found");

	certificate.version = 2;
    setSerialNumber(certificate, Date.now());

    if (CACert.subject) {
        certificate.issuer = CACert.subject;
    } else {
        setEntity(certificate.issuer, names)
    }

    setEntity(certificate.subject, names);
    setValidityPeriod(certificate, new Date(), 3650);
	certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array
    //setCABit(certificate, true, 2);
    //setKeyUsage(certificate, false, false, false, false, false, true, false);

    var names = getSubjectAltNames();
    if (names) {
        setAltName(certificate, names);
    }

    //if (CACert.subject && CACert.privateKey) {
    return createCertificateFinal(certificate, CACert.privateKey, "RSASSA-PKCS1-v1_5", "SHA-256").then(result =>
    {
        privateKey = result.privateKey;
    }) .
    then(() =>
    {
        var pemCert = convertBinaryToPem(certificate.toSchema(true).toBER(false), "CERTIFICATE");
        document.getElementById("certificate-pem").textContent = pemCert;
        var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemCert);
        document.getElementById("certificate-download").setAttribute("href", pemUrl);
    }) .
    then(() =>
    {
        crypto.exportKey("pkcs8", privateKey).
        then(pkcs8 =>
        {
            var pemPrivateKey = convertBinaryToPem(pkcs8, "PRIVATE KEY");
            document.getElementById("private-key-pem").textContent = pemPrivateKey;
            var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemPrivateKey);
            document.getElementById("private-key-download").setAttribute("href", pemUrl);
        });
    });

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

    var names = getSubjectAltNames();
    if (names) {
        setAltName(cert, names);
    }
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
    cert.serialNumber = new asn1js.Integer({value: serialNumber});
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

    var basicConstraints = new BasicConstraints(value);
    cert.extensions.push(new Extension({
        extnID: "2.5.29.19",
        critical: true,
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

    var keyUsage = new asn1js.BitString({valueHex: keyUsageBits});
    cert.extensions.push(new Extension({
        extnID: "2.5.29.15",
        critical: false,
        extnValue: keyUsage.toBER(false),
        parsedValue: keyUsage
    }));
}

function setAltName(cert, names) {
    var generalNames = new Array();
    for (var i = 0; i < names.length; i++) {
        generalNames.push(new GeneralName({
            type: 2,
            value: names[i]
        }));
    }

    var altNames = new GeneralNames({
        names: generalNames
    })
    cert.extensions.push(new Extension({
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
        var res = pemString.match(/-----BEGIN CERTIFICATE-----([a-zA-Z0-9+/=\r\n]*?)-----END CERTIFICATE-----/m);
        pemString = res[1]
    } else if (label == "privatekey") {
        var res = pemString.match(/-----BEGIN RSA PRIVATE KEY-----([a-zA-Z0-9+/=\r\n]*?)-----END RSA PRIVATE KEY-----/m);
        if (res) {
            isOpensslPrivateKey = true;
            pemString = res[1];
        } else {
            res = pemString.match(/-----BEGIN PRIVATE KEY-----([a-zA-Z0-9+/=\r\n]*?)-----END PRIVATE KEY-----/m);
            pemString = res[1];
        }
    }

    // base64 decode
	pemString = pemString.replace(/\r\n/g, "");
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
    for (var i = 0; i < subj["typesAndValues"].length; i++) {
        var ty = subj["typesAndValues"][i]["type"];
        var val = subj["typesAndValues"][i]["value"]["value_block"]["value"];
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

let uploadCache = {};

function handleOriginCert(evt) {
    var radio = document.getElementsByName("originformat");
    document.getElementById("origin-der").style.display = "none";
    document.getElementById("origin-pkcs12").style.display = "none";
    document.getElementById("origin-jks").style.display = "none";

    for (var i = 0; i < radio.length; i++) {
        if (!radio[i].checked) {
            continue;
        }

        var elem;
        if (radio[i].value == "der") {
            elem = document.getElementById("origin-der");
            elem.style.display = "block";
        } else if (radio[i].value == "new"){
            elem = document.getElementById("create-ca");
            elem.style.display = "block";
        } else {
            CACertificateInfo.type = "self-signed";
            elem = document.getElementById("self-signed");
        }
    }
}

function handleUploadDerCert(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;
    tempReader.onload =
        function(event)
        {
            var buf = event.target.result;
            const asn1 = asn1js.fromBER(buf);
            const certificate = new Certificate({schema: asn1.result});
            uploadCache["cert"] = certificate;
            var pemCert = convertBinaryToPem(certificate.toSchema(true).toBER(false), "CERTIFICATE");
            document.getElementById("certificate-pem").textContent = pemCert;
            var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemCert);
            document.getElementById("certificate-download").setAttribute("href", pemUrl);
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}

function handleUploadDerPrivateKey(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;
    tempReader.onload =
        function(event)
        {
            var buf = event.target.result;
            const asn1 = asn1js.fromBER(buf);
            const certificate = new RSAPrivateKey({schema: asn1.result});

            var pemPrivateKey = convertBinaryToPem(certificate.toSchema(true).toBER(false), "PRIVATE KEY");
            document.getElementById("private-key-pem").textContent = pemPrivateKey;
            var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pemPrivateKey);
            document.getElementById("private-key-download").setAttribute("href", pemUrl);
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}


context("Hack for Rollup.js", () =>
{
	return;

    handleWhereIsCA();
    handleFileCACert();
    handleFileCAPrivateKey();
    createCACert();
    createCert();
    copyToClipboard();
    handleOriginCert();
    handleUploadDerCert();
    handleUploadDerPrivateKey();
});
//*********************************************************************************
