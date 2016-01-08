var self = require('sdk/self');
var pageMod = require("sdk/page-mod");
var { ToggleButton } = require('sdk/ui/button/toggle');
var panels = require("sdk/panel");
var { setTimeout, clearTimeout } = require("sdk/timers");
var { Request } = require("sdk/request");
var base64 = require("sdk/base64");
var utils = require('sdk/window/utils');
var { URL } = require("sdk/url");

console.log("Instrument pages.");

/*\
|*|
|*| Some functions used to endcode / decode the signature, and the text.
|*|
\*/
var StringView = {
  b64ToUint6: function (nChr) {
    return nChr > 64 && nChr < 91 ?
      nChr - 65
    : nChr > 96 && nChr < 123 ?
      nChr - 71
    : nChr > 47 && nChr < 58 ?
      nChr + 4
    : nChr === 43 ?
      62
    : nChr === 47 ?
      63
    :
      0;
  },

  uint6ToB64: function (nUint6) {
    return nUint6 < 26 ?
      nUint6 + 65
    : nUint6 < 52 ?
      nUint6 + 71
    : nUint6 < 62 ?
      nUint6 - 4
    : nUint6 === 62 ?
      43
    : nUint6 === 63 ?
      47
    :
      65;
  },

  bytesToBase64: function (aBytes) {
    var sB64Enc = "";
    for (var nMod3, nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
      nMod3 = nIdx % 3;
      if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0)
        sB64Enc += "\r\n";
      nUint24 |= aBytes[nIdx] << (16 >>> nMod3 & 24);
      if (nMod3 === 2 || aBytes.length - nIdx === 1) {
        sB64Enc += String.fromCharCode(
          StringView.uint6ToB64(nUint24 >>> 18 & 63),
          StringView.uint6ToB64(nUint24 >>> 12 & 63),
          StringView.uint6ToB64(nUint24 >>> 6 & 63),
          StringView.uint6ToB64(nUint24 & 63));
        nUint24 = 0;
      }
    }

    return sB64Enc.replace(/A(?=A$|$)/g, "=");
  },

  base64ToBytes: function (sBase64, nBlockBytes) {
    var sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, "");
    var nInLen = sB64Enc.length;
    var nOutLen = nBlockBytes ? Math.ceil((nInLen * 3 + 1 >>> 2) / nBlockBytes) * nBlockBytes : nInLen * 3 + 1 >>> 2;
    var aBytes = new Uint8Array(nOutLen);

    for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
      nMod4 = nInIdx & 3;
      nUint24 |= StringView.b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 18 - 6 * nMod4;
      if (nMod4 === 3 || nInLen - nInIdx === 1) {
        for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
          aBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
        }
        nUint24 = 0;
      }
    }

    return aBytes;
  }
};

function innerHTMLToUTF16ArrayBuffer(unsafe_text) {
  var unsafe_data = new Uint16Array(unsafe_text.length);
  for (var i = 0; i < unsafe_text.length; i++)
    unsafe_data[i] = unsafe_text.charCodeAt(i);
  return unsafe_data;
}

/*\
|*|
|*| Callback used when some secure content is overed, this callback verifies the
|*| the signature of the content, and displays a panel which display the
|*| information to the user.
|*|
\*/

// Verify the validity of the message, and transfer the content to the
// doorhanger panel.
function secureCallback(unsafe_message) {
  console.log("Receive message from the content.");
  var unsafe_json = JSON.parse(unsafe_message);
  try {
    var unsafe_url = URL(unsafe_json.identity);
  } catch (err) {
    console.log(unsafe_message);
    console.log(err.x);
    return;
  }
  var unsafe_data = innerHTMLToUTF16ArrayBuffer(unsafe_json.text);
  var unsafe_signature = StringView.base64ToBytes(unsafe_json.signature);
  var unsafe_name = "";

  var errors = { load: [], sanity: [], crypto: [], sign: [] };
  new Promise(function (resolve, reject) {
    Request({
      url: unsafe_url,
      anonymous: true,
      onComplete: function (unsafe_identity) {
        if (unsafe_identity.status != 200) {
          errors.load.push("Unable to load identity url of secure tag.");
          reject();
          return;
        }
        if (!unsafe_identity.json) {
          errors.load.push("Unable to load read JSON content from identity url of secure tag.");
          reject();
          return;
        }
        resolve(unsafe_identity.json);
      }
    }).get();
  }).then(function (unsafe_identity) {
    // Iterate over all the keys listed in the identity file an stop after
    // finding the first signature which matches.
    unsafe_name = unsafe_identity.name;
    var unsafe_serialKeys = unsafe_identity.keys;
    var anyVerified = false;
    var tryKeys = Promise.reject();
    var crypto = utils.getMostRecentBrowserWindow().crypto;

    for (let unsafe_key of unsafe_serialKeys) {
      tryKeys = tryKeys.catch(function () {
        // Validate the key.
        if (!("algo" in unsafe_key)) {
          errors.sanity.push("Missing algo property.");
          return Promise.reject();
        }
        if (!("key" in unsafe_key)) {
          errors.sanity.push("Missing key property.");
          return Promise.reject();
        }
        if (!("key_ops" in unsafe_key.key)) {
          errors.sanity.push("Missing key_ops property.");
          return Promise.reject();
        }
        if (unsafe_key.key.key_ops.indexOf("verify") == -1) {
          errors.sanity.push("Not a verify key.");
          return Promise.reject();
        }

        let algo = unsafe_key.algo;

        return Promise.resolve(unsafe_key).then(function (unsafe_key) {
          // Convert the key into a CryptoKey
          return crypto.subtle.importKey("jwk", unsafe_key.key, unsafe_key.algo, false, ["verify"]);
        }).then(function (unsafe_key) {
          // Attempt to verify the signature of the innerHTML.
          return crypto.subtle.verify(algo, unsafe_key, unsafe_signature, unsafe_data);
        }).catch(function (err) {
          errors.crypto.push(err.message);
          return Promise.reject();
        }).then(function (isValid) {
          if (isValid)
            return Promise.resolve(unsafe_name);
          errors.sign.push("The signature does not match.");
          return Promise.reject();
        });
      });
    }

    return tryKeys;
  }).then(function (unsafe_name) {
    // Report if the signature got authentified with one of the keys.
    panel.add(unsafe_name, unsafe_url.scheme, unsafe_url.host, { verified: true });
  }, function () { /* catch */
    // Report if some signature did not 
    if (errors.sign.length)
      panel.add(unsafe_name, unsafe_url.scheme, unsafe_url.host, { verified: false });

    var msg;
    for (msg of errors.crypto)
      console.log("Crypto: Error: " + msg);
    for (msg of errors.sanity)
      console.log("Sanity: Error: " + msg);
    for (msg of errors.load)
      console.log("Request: Error: " + msg);
  });
}

/*\
|*|
|*| Doorhanger panel, which use a button as an anchor, and which is displayed a
|*| bit over the browser UI in order to highlight that this information is not
|*| produced by the content of the page, and thus it can be trusted.
|*|
\*/

var panel = (function () {
  // Add a button to the interface, which is used to hook a door-hanger
  // notification to report the validity of the secure tags.
  var button = ToggleButton({
    id: "secure-content-button",
    label: "secure-content button",
    icon: {
      "16": "./icon-16.png",
      "32": "./icon-32.png",
      "64": "./icon-64.png"
    },

    onClick: function button_onClick() {
      if (timeoutId) {
        // If the user click on the button, ignore the default timeout.
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      this.checked = !this.checked;
    },

    // If the state of the button change, then update 
    onChange: function button_onChange() {
      if (this.checked)
        showPanel();
      else
        hidePanel();
    }
  });

  var panel = panels.Panel({
    contentURL: self.data.url("panel.html"),
    contentScriptFile: self.data.url("panel.js"),

    // Set the button checked state to mirror the panel show state.
    onShow: function () { button.checked = true;  },
    onHide: function () { button.checked = false; }
  });

  function hidePanel() {
    panel.hide();
  }
  function showPanel() {
    panel.show({ position: button });
  }
  var timeoutId = null;

  return {
    add: function panel_add(name, scheme, host, status) {
      panel.port.emit("secure-content-add-report", JSON.stringify({
        name: name,
        scheme: scheme,
        host: host,
        verified: status.verified
      }));

      clearTimeout(timeoutId);
      showPanel();
      timeoutId = setTimeout(hidePanel, 5000);
    },
    remove: function panel_remove() {
      panel.port.emit("secure-content-rem-report", "");
    }
  };
})();

/*\
|*|
|*| Instrument all pages with a script which will report when the mouse over a
|*| content of a web page which is signed / ciphered.
|*|
\*/

pageMod.PageMod({
  include: ["*", "file://*"],
  contentScriptFile: self.data.url("instrument.js"),
  contentScriptWhen: "end",
  onAttach: function (page) {
    // Listen for the event from the isntrumented pages.
    page.port.on("secure-content-report", secureCallback);
  }
});


/* Keep this example for later.

// a dummy function, to show how tests work.
// to see how to test this function, look at test/test-index.js
function dummy(text, callback) {
  callback(text);
}

exports.dummy = dummy;

*/
