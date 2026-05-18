'use strict';

(function (root) {
  const SDK_ID = 'snapkit-creative-kit-sdk';
  const SDK_SRC = 'https://sdk.snapkit.com/js/v1/create.js';

  const loadSdk = () => {
    if (document.getElementById(SDK_ID)) return;
    const firstScript = document.getElementsByTagName('script')[0];
    const sdkScript = document.createElement('script');
    sdkScript.id = SDK_ID;
    sdkScript.src = SDK_SRC;
    sdkScript.async = true;
    sdkScript.defer = true;
    firstScript.parentNode.insertBefore(sdkScript, firstScript);
  };

  const initShareButtons = () => {
    if (!root.snap || !root.snap.creativekit || typeof root.snap.creativekit.initalizeShareButtons !== 'function') {
      return false;
    }

    const buttons = document.getElementsByClassName('snapchat-share-button');
    root.snap.creativekit.initalizeShareButtons(buttons);
    return true;
  };

  root.snapKitInit = function () {
    initShareButtons();
  };

  if (document.readyState !== 'loading') {
    loadSdk();
    initShareButtons();
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      loadSdk();
      initShareButtons();
    }, { once: true });
  }
}(typeof globalThis !== 'undefined' ? globalThis : window));
