const form = document.getElementById("investigation-form");
const typeInput = document.getElementById("indicator-type");
const valueInput = document.getElementById("indicator-value");
const resultMessage = document.getElementById("result-message");
const resultJson = document.getElementById("result-json");
const button = document.getElementById("investigate-button");

const placeholders = {
    ip: "Enter an IP address, e.g. 8.8.8.8",
    domain: "Enter a domain, e.g. example.com",
    sha256: "Enter a 64-character SHA-256 hash"
};

typeInput.addEventListener("change", () => {
    valueInput.placeholder = placeholders[typeInput.value];
    valueInput.value = "";
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    button.disabled = true;
    resultMessage.hidden = false;
    resultMessage.textContent = "Validating indicator...";
    resultJson.hidden = true;

    try {
        const response = await fetch("/api/investigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                type: typeInput.value,
                value: valueInput.value.trim()
            })
        });

        const data = await response.json();
        resultMessage.textContent = response.ok
            ? "Indicator validated. Threat intelligence has not been queried."
            : "Validation failed. Please review the indicator.";
        resultJson.textContent = JSON.stringify(data, null, 2);
        resultJson.hidden = false;
    } catch (error) {
        resultMessage.textContent = "Unable to contact the investigation API.";
    } finally {
        button.disabled = false;
    }
});

async function checkHealth() {
    try {
        const response = await fetch("/health");
        if (!response.ok) throw new Error("Health check failed");
        const data = await response.json();
        document.getElementById("health-status").textContent =
            data.status === "healthy" ? "Healthy" : "Unknown";
        document.getElementById("health-version").textContent =
            "Version " + data.version;
    } catch (error) {
        document.getElementById("health-status").textContent = "Unavailable";
    }
}

checkHealth();
