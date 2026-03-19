const params = new URLSearchParams(window.location.search);

const blockedUrl = params.get("url");
const reason = params.get("reason");
const risk = params.get("risk") || "medium";

const title = document.getElementById("title");
const reasonText = document.getElementById("reasonText");
const urlText = document.getElementById("urlText");
const buttons = document.getElementById("buttons");


// show url
if(blockedUrl){
    urlText.innerText = blockedUrl;
}


// MEDIUM RISK → WARNING ONLY
if(risk === "medium"){

    title.innerText = "⚠ Suspicious Website Warning";
    title.classList.add("warning");

    reasonText.innerText =
        "BrowserShield detected this page as suspicious.\n\nReason: "
        + (reason || "Potential phishing indicators detected");

    // hide buttons for medium
    buttons.style.display = "none";

    // auto continue after 3 seconds
    setTimeout(()=>{
        window.location.href = blockedUrl;
    },3000);

}


// HIGH RISK → BLOCK PAGE
else if(risk === "high"){

    title.innerText = "🚫 Dangerous Website Blocked";
    title.classList.add("block");

    reasonText.innerText =
        "BrowserShield blocked this page because it appears to be malicious.\n\nReason: "
        + (reason || "High risk phishing or malware detected");

}


// go back
function goBack(){

    if(window.history.length > 1){
        window.history.back();
    } else {
        window.location.href = "about:blank";
    }

}


// allow once
function continueAnyway(){

    if(!blockedUrl) return;

    chrome.runtime.sendMessage({
        type: "ALLOW_ONCE",
        url: blockedUrl
    });

    window.location.href = blockedUrl;

}