console.log("Load instrument.js");

// This callback is called when the user over the content of a page. It sends a
// message to the chrome to verify the validity of the content.
function secureEnterCallback(evt) {
  // Get signature information.
  var message = {
    // The identity is a URL which identify a file hosted on a server, and which provide algorithm, and 
    identity: evt.target.getAttribute("identity"),
    signature: evt.target.getAttribute("signature"),
    text: evt.target.innerHTML
  };

  // Send an asynchronous message to the chrome.
  self.port.emit("secure-content-report", JSON.stringify(message));
}

// Add the secure content over-callback to a list of DOM elements
function registerSecureCallback(node) {
  node.addEventListener("mouseenter", secureEnterCallback, false);
}
function unregisterSecureCallback(node) {
  node.removeEventListener("mouseenter", secureEnterCallback, false);
}

(function init() {
const tagName = "SECURE";

  // For each added node which has the "secure" tag name. Register a mouseover
  // callback, to get notifications in the chrome.
  var observer = new MutationObserver(function(mutations) {
    for (var mutation of mutations) {
      for (var node of mutation.addedNodes) {
        if (node.tagName == tagName)
          registerSecureCallback(node);
      }
    }
  });

  // Observes all children of the document, in order to register a
  // callback on all "secure-content" tags which are added to the DOM.
  observer.observe(document, { childList: true, subtree: true });

  // Add all event listeners from existing nodes.
  var nodeList = document.getElementsByTagName(tagName);
  for (var node of nodeList)
    registerSecureCallback(node);

  // Register a callback to remove the page instrumentation if the addon is
  // disabled.
  self.port.on("detach", function () {
    // Do not add any new event listener on DOM nodes.
    observer.disconnect();

    // Remove all event listeners from existing nodes.
    var nodeList = document.getElementsByTagName(tagName);
    for (var node of nodeList)
      unregisterSecureCallback(node);
  });
})();
