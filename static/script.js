async function analyzeEmail() {

    const message = document.getElementById("emailInput").value;

    const response = await fetch("/analyze", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            message: message
        })
    });

    const data = await response.json();

    document.getElementById("result").innerHTML = `
        <h2>Risk Score: ${data.risk_score}%</h2>
        <p><strong>Detected Suspicious Words:</strong></p>
        <p>${data.detected_words.join(", ")}</p>
    `;
}