async function analyzeEmail() {
    const message = document.getElementById("emailInput").value;

    if (!message.trim()) {
        alert("Please paste an email or message first.");
        return;
    }

    const response = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: message })
    });

    const data = await response.json();

    const color = data.risk_score >= 50 ? "#e74c3c" : "#2ecc71";

    const patternsList = data.detected_patterns.length > 0
        ? data.detected_patterns.map(p =>
            `<li><strong>${p.category.toUpperCase()}:</strong> "${p.phrase}"</li>`
          ).join("")
        : "<li>None detected</li>";

    const linksList = data.urls_found.length > 0
        ? data.urls_found.map(u =>
            `<li><strong>${u.url}</strong><ul>${u.flags.map(f => `<li>${f}</li>`).join("")}</ul></li>`
          ).join("")
        : "<li>No URLs found</li>";

    document.getElementById("result").innerHTML = `
        <hr style="margin: 20px 0;">
        <h2 style="color: ${color}">Risk Score: ${data.risk_score}%</h2>
        <h3 style="color: ${color}">Verdict: ${data.verdict}</h3>

        <p><strong>Detected Threat Indicators:</strong></p>
        <ul style="margin-top: 8px; padding-left: 20px;">
            ${patternsList}
        </ul>

        <p style="margin-top: 16px;"><strong>URLs Detected (${data.url_count}):</strong></p>
        <ul style="margin-top: 8px; padding-left: 20px;">
            ${linksList}
        </ul>
    `;
}