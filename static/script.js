async function analyzeEmail() {
    const message = document.getElementById("emailInput").value;

    if (!message.trim()) {
        alert("Please paste an email or message first.");
        return;
    }

    document.getElementById("result").innerHTML = `
        <p style="margin-top: 20px; color: #888;">Analyzing...</p>
    `;

    const response = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: message })
    });

    const data = await response.json();
    const color = data.risk_score >= 40 ? "#e74c3c" : "#2ecc71";

    const patternsList = data.detected_patterns.length > 0
        ? data.detected_patterns.map(p =>
            `<li><strong>${p.category.toUpperCase()}:</strong> "${p.phrase}"</li>`
          ).join("")
        : "<li>None detected</li>";

    const linksList = data.urls_found.length > 0
        ? data.urls_found.map(u =>
            `<li><strong>${u.url}</strong>
             <ul>${u.flags.map(f => `<li>${f}</li>`).join("")}</ul>
             </li>`
          ).join("")
        : "<li>No URLs found</li>";

    const senderSection = data.sender_domain
        ? `<p style="margin-top: 16px;">
               <strong>Sender Domain:</strong> ${data.sender_domain}
           </p>
           <ul style="padding-left: 20px;">
               ${data.sender_flags.map(f => `<li>${f}</li>`).join("")}
           </ul>`
        : `<p style="margin-top: 16px;">
               <strong>Sender:</strong> No sender domain found
           </p>`;

    // Fix newlines in highlighted message
    const highlightedHtml = data.highlighted_message
        .replace(/\n/g, "<br>");

    const resultDiv = document.getElementById("result");

    resultDiv.innerHTML = `
        <hr style="margin: 20px 0;">

        <h2 style="color: ${color}">
            Risk Score: ${data.risk_score}%
        </h2>
        <h3 style="color: ${color}">
            Verdict: ${data.verdict} — ${data.risk_level} Risk
        </h3>

        <div style="margin-top: 16px; padding: 14px; background: #f9f9f9; border-radius: 10px; border-left: 4px solid ${color};">
            <strong>🤖 AI Explanation:</strong>
            <p style="margin-top: 8px; line-height: 1.6;">${data.explanation}</p>
        </div>

        <div style="margin-top: 16px; padding: 14px; background: #f9f9f9; border-radius: 10px;">
            <strong>📧 Highlighted Message:</strong>
            <div style="margin-top: 8px; line-height: 1.8; font-family: monospace; font-size: 0.9rem;">
                ${highlightedHtml}
            </div>
        </div>

        <p style="margin-top: 16px;">
            <strong>Detected Threat Indicators:</strong>
        </p>
        <ul style="margin-top: 8px; padding-left: 20px;">
            ${patternsList}
        </ul>

        <p style="margin-top: 16px;">
            <strong>URLs Detected (${data.url_count}):</strong>
        </p>
        <ul style="margin-top: 8px; padding-left: 20px;">
            ${linksList}
        </ul>

        ${senderSection}

        <p style="margin-top: 16px;">
            <strong>Score Breakdown:</strong>
        </p>
        <ul style="padding-left: 20px;">
            <li>Language: ${data.score_breakdown.language}%</li>
            <li>Links: ${data.score_breakdown.links}%</li>
            <li>Sender: ${data.score_breakdown.sender}%</li>
        </ul>
    `;
}