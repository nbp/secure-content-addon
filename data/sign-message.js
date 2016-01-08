function textToUTF16ArrayBuffer(text) {
  var data = new Uint16Array(text.length);
  for (var i = 0; i < text.length; i++)
    data[i] = text.charCodeAt(i);
  return data;
}

function sign() {
  var keys = window.localStorage.getItem("keys");
  keys = JSON.parse(keys);

  var algo = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"},
  };
  var promise = null;
  var crypto = window.crypto.subtle;

  if (!keys || !keys.publicKey || !keys.privateKey) {
    promise = crypto.generateKey(
      algo,
      true,
      ["sign", "verify"] //can be any combination of "sign" and "verify"
    ).then(function(keyPair) {
      //returns a keypair object
      console.log(keyPair);
      return keyPair;
    }).catch(function(err) {
      console.error(err);
    });
  } else {
    promise = Promise.all([
      window.crypto.subtle.importKey("jwk", keys.publicKey, algo, true, ["verify"]),
      window.crypto.subtle.importKey("jwk", keys.privateKey, algo, true, ["sign"])
    ]).then(function (keys) {
      return {
        publicKey: keys[0],
        privateKey: keys[1]
      };
    });
  }

  promise = promise.then(function (keyPair) {
    Promise.all([
      crypto.exportKey("jwk", keyPair.publicKey).catch(function (err) {
        console.error(err);
      }),

      crypto.exportKey("jwk", keyPair.privateKey).catch(function (err) {
        console.error(err);
      })
    ]).then(function (keys) {
      document.getElementById("pubkey").value = JSON.stringify({
        name: document.getElementById("name").value,
        keys: [{ algo: algo, key: keys[0] }]
      }, null, 2);
      document.getElementById("prvkey").value = JSON.stringify(keys[1]);
      keys = { publicKey: keys[0], privateKey: keys[1] };
      window.localStorage.setItem("keys", JSON.stringify(keys));
    });
    return keyPair;
  });

  var loc = document.getElementById("identity").value;
  var text = document.getElementById("text").value;
  var data = textToUTF16ArrayBuffer(text);
  promise.then(function (keyPair) {
    return crypto.sign(algo, keyPair.privateKey, data);
  }).then(function (signBytes) {
    var signText = StringView.bytesToBase64(new Uint8Array(signBytes));
    document.getElementById("signedText").value =
      "<secure identity=\"" + loc + "\" signature=\"" + signText + "\">" + text + "</secure>";
  }).catch(function (err) {
    console.error(err);
  });
}
