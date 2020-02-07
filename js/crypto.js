
var chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Use a lookup table to find the index.
var lookup = new Uint8Array(256);
for (var i = 0; i < chars.length; i++) {
    lookup[chars.charCodeAt(i)] = i;
}

var base64urlToArrayBuffer = function(base64url) {
    var bufferLength = base64url.length * 0.75,
        len = base64url.length, i, p = 0,
        encoded1, encoded2, encoded3, encoded4;

    if (base64url[base64url.length - 1] === "=") {
        bufferLength--;
        if (base64url[base64url.length - 2] === "=") {
            bufferLength--;
        }
    }

    var arrayBuffer = new ArrayBuffer(bufferLength),
        bytes = new Uint8Array(arrayBuffer);

    for (i = 0; i < len; i+=4) {
        encoded1 = lookup[base64url.charCodeAt(i)];
        encoded2 = lookup[base64url.charCodeAt(i+1)];
        encoded3 = lookup[base64url.charCodeAt(i+2)];
        encoded4 = lookup[base64url.charCodeAt(i+3)];

        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }

    return arrayBuffer;
};

var arrayBufferToBase64url = function(arrayBuffer) {
    var bytes = new Uint8Array(arrayBuffer),
        i, len = bytes.length, base64url = "";

    for (i = 0; i < len; i+=3) {
        base64url += chars[bytes[i] >> 2];
        base64url += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64url += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64url += chars[bytes[i + 2] & 63];
    }

    if ((len % 3) === 2) {
        base64url = base64url.substring(0, base64url.length - 1) + "=";
    } else if (len % 3 === 1) {
        base64url = base64url.substring(0, base64url.length - 2) + "==";
    }

    return base64url;
};

var trimParam = function(param) {
    while ((param[0] === 0) && (param[1] >= 0)) {
        subSig = subSig.slice(1);
    }
};

var IEEEtoDER = function(IEEESig) {
    IEEESig = new Int8Array(IEEESig);

    var paramSize = IEEESig.length / 2;

    var r = IEEESig.slice(0, paramSize);
    var s = IEEESig.slice(paramSize);

    trimParam(r);
    trimParam(s);

    var rsLength = r.length + s.length;

    var result = new Uint8Array(6 + rsLength);
    result[0] = 0x30;
    result[1] = rsLength + 4;
    result[2] = 0x02;
    result[3] = r.length;
    result.set(r, 4);
    result[r.length + 4] = 0x02;
    result[r.length + 5] = s.length;
    result.set(s, r.length + 6);

    return result;
};

var DERtoIEEE = function(DERSig) {
    DERSig = new Int8Array(DERSig);

    var rLength = DERSig[3];
    var beg = 4;
    var end = beg + rLength;
    var r = DERSig.slice(beg, end);

    var sLength = DERSig[rLength + 5];
    var beg = rLength + 6;
    var end = beg + sLength;
    var s = DERSig.slice(beg, end);

    var rPad = new Uint8Array();
    while ((rPad.length + r.length) < s.length) {
        rPad = new Uint8Array(rPad.length + 1);
    }

    var sPad = new Uint8Array();
    while ((sPad.length + s.length) < r.length) {
        sPad = new Uint8Array(sPad.length + 1);
    }

    var result =
        new Uint8Array(rPad.length + r.length + sPad.length + s.length);
    result.set(rPad, 0);
    result.set(r, rPad.length);
    result.set(sPad, rPad.length + r.length);
    result.set(s, rPad.length + r.length + sPad.length);

    return result;
};

var verify = function(publicKey, signature, data) {
    return new Promise((resolve) => {
        crypto.subtle.importKey(
            "raw", publicKey,
            { name: "ECDSA", namedCurve: "P-256" },
            false, ["verify"])
            .then(function(publicKey) {
                crypto.subtle.verify(
                    { name: "ECDSA", hash : {name: "SHA-256"} },
                    // { name: "ECDSA", hash : "SHA-256"},
                    publicKey, signature, data)
                    .then(resolve);
            });
    });
};

var sign = function(privateKey, data) {
    return new Promise((resolve) => {
        crypto.subtle.importKey(
            "pkcs8", privateKey,
            { name: "ECDSA", namedCurve: "P-256" },
            false, ["sign"])
            .then(function(privateKey) {
                crypto.subtle.sign(
                    { name: "ECDSA", hash : "SHA-256"},
                    privateKey, data)
                    .then(resolve);
            });
    });
};

window.onload = function() {
    var signButton = document.getElementById("sign");

    signButton.onclick = function(e) {
        var privateKeyBase64urlElem =
            document.getElementById("privateKeyBase64url");
        var dataStringElem = document.getElementById("dataString");
        var signatureBase64urlElem =
            document.getElementById("signatureBase64url");

        var privateKeyBase64url = privateKeyBase64urlElem.value;
        var dataString = dataStringElem.value;
        var signatureBase64url = signatureBase64urlElem.value;

        var privateKey = base64urlToArrayBuffer(privateKeyBase64url);
        var data = new TextEncoder("utf-8").encode(dataString);

        sign(privateKey, data).then(function(signature) {
            signature = IEEEtoDER(signature);
            signatureBase64urlElem.value = arrayBufferToBase64url(signature);
        });
    };

    var verifyButton = document.getElementById("verify");

    verifyButton.onclick = function(e) {
        var publicKeyBase64urlElem =
            document.getElementById("publicKeyBase64url");
        var dataStringElem = document.getElementById("dataString");
        var signatureBase64urlElem =
            document.getElementById("signatureBase64url");
        var verifiedResultElem = document.getElementById("verified");

        var publicKeyBase64url = publicKeyBase64urlElem.value;
        var dataString = dataStringElem.value;
        var signatureBase64url = signatureBase64urlElem.value;

        var publicKey = base64urlToArrayBuffer(publicKeyBase64url);
        var data = new TextEncoder("utf-8").encode(dataString);
        var signature = DERtoIEEE(base64urlToArrayBuffer(signatureBase64url));

        verify(publicKey, signature, data).then(function(verified) {
            verifiedResultElem.innerText = verified;
        });
    }
}

