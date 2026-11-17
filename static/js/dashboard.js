const form = document.getElementById("investigation-form");
const typeInput = document.getElementById("indicator-type");
const valueInput = document.getElementById("indicator-value");
const resultMessage = document.getElementById("result-message");
const resultJson = document.getElementById("result-json");
const results = document.getElementById("intelligence-results");
const button = document.getElementById("investigate-button");

const placeholders = {
    ip: "Enter an IP address, e.g. 8.8.8.8",
    domain: "Enter a domain, e.g. example.com",
    sha256: "Enter a 64-character SHA-256 hash"
};

function setText(id, value) {
    document.getElementById(id).textContent =
        value === null || value === undefined || value === ""
            ? "Not available"
            : String(value);
}

function formatRecords(records) {
    return Array.isArray(records) && records.length
        ? records.filter(value => value !== null && value !== undefined)
            .join(", ") || "Not available"
        : "Not available";
}

function displayResults(data) {
    const indicator = data.indicator || {};
    const intel = data.intelligence || {};
    const network = intel.network || {};
    const dns = intel.dns || {};
    const source = intel.source || {};
    const reputation = intel.reputation || {};
    const isDomain = indicator.type === "domain";
    const isHash = indicator.type === "sha256";

    results.hidden = false;
    resultMessage.hidden = true;

    // Network/DNS cards do not apply to SHA-256 investigations.
    document.getElementById("intel-network-card-1").hidden = isHash;
    document.getElementById("intel-network-card-2").hidden = isHash;

    setText("intel-indicator", indicator.value);
    setText("intel-status", data.intelligence_status || data.status);

    document.getElementById("intel-prefix-label").textContent =
        isDomain ? "IPv4 ADDRESSES (A)" : "NETWORK PREFIX";

    document.getElementById("intel-asn-label").textContent =
        isDomain ? "IPv6 ADDRESSES (AAAA)" : "ORIGIN ASN";

    if (isDomain) {
        setText("intel-prefix", formatRecords(dns.A));
        setText("intel-asn", formatRecords(dns.AAAA));
        setText("intel-mx", formatRecords(dns.MX));
    } else {
        setText("intel-prefix", network.prefix);
        setText(
            "intel-asn",
            Array.isArray(network.asns) && network.asns.length
                ? network.asns.map(asn => "AS" + asn).join(", ")
                : null
        );
        setText("intel-mx", null);
    }

    document.getElementById("intel-dns-extra").hidden = !isDomain;

    // Show reputation statistics only when a real lookup completed.
    const hasReputation = isHash &&
        data.intelligence_status === "completed" &&
        intel.reputation &&
        typeof reputation.malicious === "number" &&
        typeof reputation.suspicious === "number" &&
        typeof reputation.harmless === "number" &&
        typeof reputation.undetected === "number";

    document.getElementById("intel-hash-extra").hidden = !hasReputation;

    if (hasReputation) {
        setText("intel-malicious", reputation.malicious);
        setText("intel-suspicious", reputation.suspicious);
        setText("intel-harmless", reputation.harmless);
        setText("intel-undetected", reputation.undetected);
    }

    setText("intel-verdict", data.verdict || "unknown");
    setText("intel-source", source.provider);
    setText(
        "intel-timestamp",
        intel.queried_at_utc
            ? "Investigation timestamp (UTC): " + intel.queried_at_utc
            : "No external intelligence timestamp available"
    );
    setText(
        "intel-note",
        data.message || "No additional investigation details available."
    );

    const sourceLink = document.getElementById("intel-source-link");
    const endpoint = source.endpoint;

    const trustedSources = [
        "https://stat.ripe.net/data/network-info/data.json",
        "https://dns.google/resolve"
    ];

    const expectedVirusTotalUrl =
        "https://www.virustotal.com/gui/file/" + indicator.value;

    if (typeof endpoint === "string" &&
        trustedSources.includes(endpoint)) {
        sourceLink.href = endpoint;
        sourceLink.hidden = false;
    } else if (
        isHash &&
        hasReputation &&
        source.provider === "VirusTotal" &&
        source.report_url === expectedVirusTotalUrl
    ) {
        sourceLink.href = expectedVirusTotalUrl;
        sourceLink.hidden = false;
    } else {
        sourceLink.hidden = true;
        sourceLink.removeAttribute("href");
    }

    resultJson.textContent = JSON.stringify(data, null, 2);
    resultJson.hidden = false;
}

typeInput.addEventListener("change", () => {
    valueInput.placeholder = placeholders[typeInput.value];
    valueInput.value = "";
    lastInvestigatedIndicator = null;
    reportButton.hidden = true;
    reportMessage.textContent = "";
    results.hidden = true;
    resultJson.hidden = true;
    resultMessage.hidden = false;
    resultMessage.textContent = "Select an indicator and begin investigation.";
});

const reportButton = document.getElementById("download-report-button");
const reportMessage = document.getElementById("report-download-message");
let lastInvestigatedIndicator = null;

reportButton.addEventListener("click", async () => {
    if (!lastInvestigatedIndicator || reportButton.disabled) return;

    reportButton.disabled = true;
    reportMessage.textContent = "Generating PDF report...";

    try {
        const response = await fetch("/api/report", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(lastInvestigatedIndicator)
        });

        if (!response.ok) {
            let message = "Unable to generate PDF report.";
            try {
                const errorData = await response.json();
                message = errorData.error || errorData.result?.reason || message;
            } catch (_) {
                // Keep the default error message.
            }
            throw new Error(message);
        }

        const pdfBlob = await response.blob();

        if (!pdfBlob.type.includes("pdf")) {
            throw new Error("The server did not return a PDF.");
        }

        const downloadUrl = URL.createObjectURL(pdfBlob);
        const link = document.createElement("a");
        link.href = downloadUrl;
        link.download = "CyberSentinel_Investigation_Report.pdf";
        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
        reportMessage.textContent = "PDF report download started.";

    } catch (error) {
        reportMessage.textContent = error.message;
    } finally {
        reportButton.disabled = false;
    }
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    button.disabled = true;
    lastInvestigatedIndicator = null;
    reportButton.hidden = true;
    reportMessage.textContent = "";
    results.hidden = true;
    resultJson.hidden = true;
    resultMessage.hidden = false;
    resultMessage.textContent = "Investigating indicator...";

    try {
        const response = await fetch("/api/investigate", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                type: typeInput.value,
                value: valueInput.value.trim()
            })
        });

        const data = await response.json();

        if (!response.ok) {
            resultMessage.textContent =
                data.error ||
                data.result?.reason ||
                "Invalid indicator. Please check your input.";
            return;
        }

        displayResults(data);

        lastInvestigatedIndicator = {
            type: typeInput.value,
            value: valueInput.value.trim()
        };
        reportButton.hidden = false;

    } catch (error) {
        resultMessage.textContent =
            "Unable to contact the investigation API.";
    } finally {
        button.disabled = false;
    }
});

async function checkHealth() {
    try {
        const response = await fetch("/health");

        if (!response.ok) {
            throw new Error("Health check failed");
        }

        const data = await response.json();

        setText(
            "health-status",
            data.status === "healthy" ? "Healthy" : "Unknown"
        );
        setText("health-version", "Version " + data.version);

    } catch (error) {
        setText("health-status", "Unavailable");
    }
}

checkHealth();
