const HOST_NAME = 'com.infrasight.remote';

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  chrome.runtime.sendNativeMessage(HOST_NAME, message, (response) => {
    if (chrome.runtime.lastError) {
      sendResponse({ ok: false, error: chrome.runtime.lastError.message });
      return;
    }
    sendResponse(response);
  });
  return true;
});
