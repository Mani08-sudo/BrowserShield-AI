const BACKEND = "http://127.0.0.1:5000";

console.log("BrowserShield service worker started");

const scanned = new Set();
const allowOnce = new Set();

const SKIP_PATTERNS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "chrome://",
    "chrome-extension://",
    "edge://",
    "about:"
];


// ===============================
// OPEN DASHBOARD WHEN INSTALLED
// ===============================
chrome.runtime.onInstalled.addListener(() => {

    chrome.tabs.create({
        url: "http://127.0.0.1:5000/dashboard"
    });

});


// ===============================
// OPEN DASHBOARD ON START
// ===============================
chrome.runtime.onStartup.addListener(() => {

    chrome.tabs.create({
        url: "http://127.0.0.1:5000/dashboard"
    });

});


// ===============================
// URL ANALYSIS
// ===============================
async function analyzeUrl(url){

    try{

        const res = await fetch(`${BACKEND}/api/predict/url`,{
            method:"POST",
            headers:{ "Content-Type":"application/json" },
            body:JSON.stringify({ url })
        });

        return await res.json();

    }catch(err){

        console.error("Backend unreachable:",err);
        return null;

    }

}


// ===============================
// REAL-TIME NAVIGATION INTERCEPT
// ===============================
chrome.webNavigation.onBeforeNavigate.addListener(async(details)=>{

    const url = details.url;
    const tabId = details.tabId;

    if(!url.startsWith("http")) return;

    if(SKIP_PATTERNS.some(p=>url.includes(p))) return;

    if(allowOnce.has(url)){
        allowOnce.delete(url);
        return;
    }

    if(scanned.has(url)) return;
    scanned.add(url);

    console.log("Scanning:",url);

    const result = await analyzeUrl(url);
    if(!result) return;

    const risk = result.risk || "low";
    const reason = result.reason || "Suspicious activity detected";


    // ===============================
    // HIGH RISK → BLOCK PAGE
   // ===============================
    if (risk === "high") {

     console.log("HIGH RISK detected:", url);

     // badge indicator
     chrome.action.setBadgeText({ tabId, text: "!" });
     chrome.action.setBadgeBackgroundColor({ tabId, color: "#ff4c4c" });

     // redirect to warning page
     const warningUrl = chrome.runtime.getURL(
         `warning.html?url=${encodeURIComponent(url)}&risk=high&reason=${encodeURIComponent(reason)}`
     );

     chrome.tabs.update(tabId, { url: warningUrl });

     // show notification
     chrome.notifications.create({
         type: "basic",
         iconUrl: "icon48.png",
         title: "BrowserShield: Dangerous Website Blocked",
         message: reason
     });

    }

    // ===============================
    // MEDIUM RISK
    // ===============================
    else if(risk==="medium"){

        const warningUrl = chrome.runtime.getURL(
            `warning.html?url=${encodeURIComponent(url)}&risk=medium&reason=${encodeURIComponent(reason)}`
        );

        chrome.tabs.update(tabId,{url:warningUrl});

    }

    // ===============================
    // SAFE
    // ===============================
    else{

        chrome.action.setBadgeText({tabId,text:"✓"});
        chrome.action.setBadgeBackgroundColor({tabId,color:"#39d98a"});

        setTimeout(()=>{
            chrome.action.setBadgeText({tabId,text:""});
        },3000);

    }

});


// ===============================
// ALLOW ONCE
// ===============================
chrome.runtime.onMessage.addListener((msg)=>{

    if(msg.type==="ALLOW_ONCE" && msg.url){

        console.log("Allow once:",msg.url);
        allowOnce.add(msg.url);

    }

});