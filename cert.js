
let CACertificateInfo = {
    type: "self-signed",
    upload: {},
    created: {},
};

function checkCACertificate() {
    var ty = CACertificateInfo.type;
    if (ty == "self-signed") {
        return false;
    }

    if (ty == "upload") {
        return CACertificateInfo.upload;
    }

    if (ty == "created") {
        return {
            cert:document.getElementById("ca-cert-pem").textContent,
            pkey:document.getElementById("ca-private-key-pem").textContent,
        };
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
            CACertificateInfo.upload.cert = event.target.result;
        };
    tempReader.readAsText(currentFiles[0]);
}

function handleFileCAPrivateKey(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;

    tempReader.onload =
        function(event)
        {
            CACertificateInfo.upload.pkey = event.target.result;
        };
    tempReader.readAsText(currentFiles[0]);
}

function fmt(num, length) {
    var r = num.toString();
    if (r.length<length) r = Array(length - r.length + 1).join('0') + r;
    return r;
}
function time2str(t) {
    var s = fmt(t.getFullYear(), 4) + "-" + fmt(t.getMonth()+1, 2) + "-" + fmt(t.getDate(), 2);
    s = s + " " + fmt(t.getHours(), 2) + ":" + fmt(t.getMinutes(), 2) + ":" + fmt(t.getSeconds(), 2);
    return s;
}


function setCACertContent(cert, pkey) {
    document.getElementById("ca-cert-pem").textContent = cert;
    var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(cert);
    document.getElementById("ca-certificate-download").setAttribute("href", pemUrl);

    document.getElementById("ca-private-key-pem").textContent = pkey;
    var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pkey);
    document.getElementById("ca-private-key-download").setAttribute("href", pemUrl);
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

    var certinfo = {
        subject: names,
        isCA: true,
    }

    let sequence = Promise.resolve();
    sequence = sequence.then(() => {

        return crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
        );
    });

    sequence = sequence.then(keypair=> {
        return crypto.subtle.exportKey("pkcs8", keypair.privateKey);
    })

    sequence = sequence.then(pkcs8=>{
        var buf = new Uint8Array(pkcs8);
        wasmCreateCACertificate(buf, certinfo, setCACertContent);       
    });
}


function getSubjectAltNames() {
    var elem = document.getElementById("subject-alt-name");
    var str = elem.value.toLowerCase();
    var strs = str.split(/[ ,]+/);

    return strs;
}

function setCertContent(cert, pkey) {
    document.getElementById("certificate-pem").textContent = cert;
    var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(cert);
    document.getElementById("certificate-download").setAttribute("href", pemUrl);

    document.getElementById("private-key-pem").textContent = pkey;
    var pemUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pkey);
    document.getElementById("private-key-download").setAttribute("href", pemUrl);
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

    var certinfo = {
        subject: names,
        isCA: false,
    };

    var startTime = document.getElementById("validity-not-before").value;
    var endTime = document.getElementById("validity-not-after").value;
    if (startTime != "") {
        t = new Date(startTime);
        t.setMinutes(t.getMinutes() + t.getTimezoneOffset());
        certinfo["not before"] = time2str(t);
    }
    if (endTime != "") {
        t = new Date(endTime);
        t.setMinutes(t.getMinutes() + t.getTimezoneOffset());
        certinfo["not after"] = time2str(t);
    }


    var elem = document.getElementById("subject-alt-name");
    var str = elem.value.toLowerCase();
    var strs = str.split(/[ ,]+/);
    if (strs) {
        certinfo["subject-alt-name"] = strs
    }

    var extKeyUsage = new Array();
    var ekus = document.getElementsByName("cert-eku");
    for (i = 0; i < ekus.length; i++) {
        if (ekus[i].checked) {
            extKeyUsage.push(ekus[i].value);
        }
    }
    if (extKeyUsage.length > 0) {
        certinfo["extendkeyusage"] = extKeyUsage
    }

    var keyUsage = new Array();
    var kus = document.getElementsByName("cert-ku");
    for (i = 0; i < kus.length; i++) {
        if (kus[i].checked) {
            keyUsage.push(kus[i].value);
        }
    }
    if (keyUsage.length > 0) {
        certinfo["keyusage"] = keyUsage;
    }

    var ca = checkCACertificate();

    let sequence = Promise.resolve();
    sequence = sequence.then(() => {

        return crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
        );
    });

    sequence = sequence.then(keypair=> {
        return crypto.subtle.exportKey("pkcs8", keypair.privateKey);
    })
    sequence = sequence.then(pkcs8=>{
        var buf = new Uint8Array(pkcs8);
        if (typeof ca == "object") {
            wasmCreateCertificate(buf, certinfo, ca, setCertContent);
        } else {
            wasmCreateCertificate(buf, certinfo, undefined, setCertContent);
        }
    });
}


function setPEMContent(cert, pkey) {
    if (typeof cert != "undefined") {
        pemCertUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(cert)
        document.getElementById("certificate-pem").textContent = cert
        document.getElementById("certificate-download").setAttribute("href", pemCertUrl)
    }

    if (typeof pkey != "undefined") {
        pemPkeyUrl = "data:application/octet-stream;charset=UTF-8;base64," + btoa(pkey)
        document.getElementById("private-key-pem").textContent = pkey
        document.getElementById("private-key-download").setAttribute("href", pemPkeyUrl)
    }
}

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
        } else if (radio[i].value == "pkcs12"){
            elem = document.getElementById("origin-pkcs12");
            elem.style.display = "block";
        } else {
            elem = document.getElementById("origin-jks");
            elem.style.display = "block"
        }
    }
}

function handleUploadDerCert(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;
    tempReader.onload =
        function(event)
        {
            var buf = new Uint8Array(event.target.result);
            wasmDer2Pem(buf, "cert", setPEMContent);
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}

function handleUploadDerPrivateKey(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;
    tempReader.onload =
        function(event)
        {
            var buf = new Uint8Array(event.target.result);
            wasmDer2Pem(buf, "pkey", setPEMContent);
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}

function handleUploadPKCS12Cert(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;
    tempReader.onload =
        function(event)
        {
            var password = document.getElementById("pkcs12-password").value;

            var dst = new Uint8Array(event.target.result);
            var buf = Module._malloc(dst.length * dst.BYTES_PER_ELEMENT);
            var certbuf = Module._malloc(20480);
            var pkeybuf = Module._malloc(20480);
            Module.HEAPU8.set(dst, buf);
            var result = Module.ccall('pkcs122pem', 'number', ['number', 'number', 'string', 'number', 'number'], [buf, dst.length, password, certbuf, pkeybuf]);
            if (result == 0) {
                cert = Pointer_stringify(certbuf);
                pkey = Pointer_stringify(pkeybuf);
                setPEMContent(cert, pkey);
            } else {
                console.log("failed");
            }
            Module._free(buf);
            Module._free(certbuf);
            Module._free(pkeybuf);
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}

function handleUploadJKS(input) {
    const tempReader = new FileReader();
    const currentFiles = input.files;
    tempReader.onload =
        function(event)
        {
            var dst = new Uint8Array(event.target.result);
            var passwd = document.getElementById("jks-password").value;
            jks2pem(dst, passwd, setPEMContent);
        };
    tempReader.readAsArrayBuffer(currentFiles[0]);
}
