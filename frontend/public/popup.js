const openButton = document.getElementById("open-analyzer");
const errorMessage = document.getElementById("popup-error");

openButton.addEventListener("click", async () => {
  errorMessage.hidden = true;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) throw new Error("Open a normal website before launching the analyzer.");

    await chrome.sidePanel.open({ tabId: tab.id });
    window.close();
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
});
