
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

window.onload = function() {
    var submitButton = document.getElementById("submit");

    submitButton.onclick = function(e) {
        var privateKeyBase64urlElem =
            document.getElementById("privateKeyBase64url");
        var dataStringElem = document.getElementById("dataString");
        var resultElem = document.getElementById("signature");

        var privateKeyBase64url = privateKeyBase64urlElem.value;
        var dataString = dataStringElem.value;

        var privateKey = base64urlToArrayBuffer(privateKeyBase64url);
        var data = base64urlToArrayBuffer(dataString);

        crypto.subtle.importKey(
            "pkcs8", privateKey,
            { name: "ECDSA", namedCurve: "P-256" },
            false, ["sign"])
            .then(function(privateKey) {
                crypto.subtle.sign(
                    // { name: "ECDSA", hash : {name: "SHA-256"} },
                    { name: "ECDSA", hash : "SHA-256"},
                    privateKey, data)
                    .then(function(signature) {
                        resultElem.innerText =
                            arrayBufferToBase64url(signature);
                    });
            });

    };
}

