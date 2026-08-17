function scanURL() {

    const urlInput = document.getElementById("urlInput");
    const url = urlInput.value.trim();

    const resultCard = document.getElementById("resultCard");
    const resultIcon = document.getElementById("resultIcon");
    const resultTitle = document.getElementById("resultTitle");
    const resultMessage = document.getElementById("resultMessage");
    const riskScore = document.getElementById("riskScore");
    const riskProgress = document.getElementById("riskProgress");

    // Check if URL is empty
    if (url === "") {
        resultIcon.textContent = "⚠️";
        resultTitle.textContent = "URL Required";
        resultMessage.textContent = "Please enter a website URL to scan.";
        riskScore.textContent = "0%";
        riskProgress.style.width = "0%";
        return;
    }

    // Basic URL validation
    let validURL;

    try {
        validURL = new URL(url);
    } catch (error) {
        resultIcon.textContent = "❌";
        resultTitle.textContent = "Invalid URL";
        resultMessage.textContent =
            "Please enter a valid URL such as https://example.com";

        riskScore.textContent = "0%";
        riskProgress.style.width = "0%";

        return;
    }

    // Show scanning message
    resultIcon.textContent = "🔄";
    resultTitle.textContent = "Analyzing Website...";
    resultMessage.textContent =
        "Checking URL characteristics and security indicators.";

    riskScore.textContent = "...";
    riskProgress.style.width = "20%";

    // Simulated analysis
    setTimeout(function () {

        let risk = 0;
        let reasons = [];

        const hostname = validURL.hostname.toLowerCase();

        // HTTPS check
        if (validURL.protocol !== "https:") {
            risk += 20;
            reasons.push("Website does not use HTTPS.");
        }

        // URL length
        if (url.length > 75) {
            risk += 15;
            reasons.push("URL is unusually long.");
        }

        // Suspicious symbols
        if (url.includes("@")) {
            risk += 25;
            reasons.push("URL contains an @ symbol.");
        }

        // IP address instead of domain
        const ipPattern =
            /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

        if (ipPattern.test(url)) {
            risk += 30;
            reasons.push("Website uses an IP address instead of a domain name.");
        }

        // Suspicious keywords
        const suspiciousWords = [
            "login",
            "verify",
            "verification",
            "password",
            "account",
            "secure",
            "update",
            "bank",
            "confirm"
        ];

        let foundWords = [];

        suspiciousWords.forEach(function(word) {
            if (hostname.includes(word)) {
                foundWords.push(word);
            }
        });

        if (foundWords.length > 0) {
            risk += 20;
            reasons.push(
                "Suspicious keyword detected: " +
                foundWords.join(", ")
            );
        }

        // Multiple hyphens
        const hyphenCount = (hostname.match(/-/g) || []).length;

        if (hyphenCount >= 3) {
            risk += 15;
            reasons.push("Domain contains multiple hyphens.");
        }

        // Limit risk to 100
        risk = Math.min(risk, 100);

        // Display result
        riskScore.textContent = risk + "%";
        riskProgress.style.width = risk + "%";

        if (risk >= 60) {

            resultIcon.textContent = "🚨";
            resultTitle.textContent = "Potentially Phishing";
            resultMessage.textContent =
                "This URL contains characteristics commonly associated with phishing websites.";

        } else if (risk >= 30) {

            resultIcon.textContent = "⚠️";
            resultTitle.textContent = "Suspicious Website";
            resultMessage.textContent =
                "This URL contains some suspicious characteristics. Proceed carefully.";

        } else {

            resultIcon.textContent = "🟢";
            resultTitle.textContent = "Low Risk";
            resultMessage.textContent =
                "No major suspicious URL characteristics were detected.";

        }

        // Display reasons
        if (reasons.length > 0) {

            resultMessage.innerHTML +=
                "<br><br><strong>Indicators:</strong><br>" +
                reasons.join("<br>");

        }

    }, 1500);
}