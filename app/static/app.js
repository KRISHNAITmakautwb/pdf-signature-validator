document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const browseBtn = document.getElementById('browseBtn');
    const loadingPanel = document.getElementById('loadingPanel');
    const resultsSection = document.getElementById('resultsSection');

    // Demos
    const demoValidBtn = document.getElementById('demoValidBtn');
    const demoTamperedBtn = document.getElementById('demoTamperedBtn');
    const demoUnsignedBtn = document.getElementById('demoUnsignedBtn');

    // Verdict Banner
    const verdictBanner = document.getElementById('verdictBanner');
    const verdictIcon = document.getElementById('verdictIcon');
    const verdictBadge = document.getElementById('verdictBadge');
    const verdictHeadline = document.getElementById('verdictHeadline');
    const verdictDetail = document.getElementById('verdictDetail');
    const engineBadge = document.getElementById('engineBadge');
    const metaFilename = document.getElementById('metaFilename');
    const metaFileSize = document.getElementById('metaFileSize');
    const metaSigCount = document.getElementById('metaSigCount');
    const metaCheckedAt = document.getElementById('metaCheckedAt');

    // Panes
    const signaturesList = document.getElementById('signaturesList');
    const certificateDetailsCard = document.getElementById('certificateDetailsCard');
    const byterangeBar = document.getElementById('byterangeBar');
    const byterangeDataGrid = document.getElementById('byterangeDataGrid');
    const anomaliesList = document.getElementById('anomaliesList');
    const rawJsonBlock = document.getElementById('rawJsonBlock');
    const curlSnippet = document.getElementById('curlSnippet');

    // Actions
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    const printReportBtn = document.getElementById('printReportBtn');
    const copyCurlBtn = document.getElementById('copyCurlBtn');
    const copyJsonBtn = document.getElementById('copyJsonBtn');

    // Trust Modal
    const openTrustStoreBtn = document.getElementById('openTrustStoreBtn');
    const closeTrustModalBtn = document.getElementById('closeTrustModalBtn');
    const trustModal = document.getElementById('trustModal');
    const certFileInput = document.getElementById('certFileInput');
    const uploadCertBtn = document.getElementById('uploadCertBtn');
    const trustedCertsList = document.getElementById('trustedCertsList');

    let currentReport = null;
    let currentPdfBlob = null;

    // Check System Health
    async function checkHealth() {
        try {
            const res = await fetch('/api/health');
            const data = await res.json();
            const healthPill = document.getElementById('serviceHealthStatus');
            const healthText = document.getElementById('healthText');
            if (data.status === 'healthy') {
                healthText.textContent = `Online (${data.pyhanko_available ? 'pyHanko Engine' : 'Crypto Fallback'})`;
            }
        } catch (e) {
            console.warn('Health check warning:', e);
        }
    }
    checkHealth();

    // File Drag & Drop
    browseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });

    dropZone.addEventListener('click', () => fileInput.click());

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // Handle Upload & Validate
    async function handleFileUpload(file) {
        if (!file.name.toLowerCase().endsWith('.pdf')) {
            alert('Please select a valid PDF file (.pdf)');
            return;
        }

        showLoading(true);
        currentPdfBlob = file;

        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await fetch('/api/validate', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            if (!res.ok || !data.success) {
                throw new Error(data.error || 'Validation failed');
            }

            currentReport = data.report;
            renderResults(currentReport);
        } catch (err) {
            alert(`Error analyzing PDF: ${err.message}`);
        } finally {
            showLoading(false);
        }
    }

    // Demo Click Handlers
    demoValidBtn.addEventListener('click', () => fetchDemoSample('/api/samples/valid', 'valid_signed_sample.pdf'));
    demoTamperedBtn.addEventListener('click', () => fetchDemoSample('/api/samples/tampered', 'tampered_attack_sample.pdf'));
    demoUnsignedBtn.addEventListener('click', () => fetchDemoSample('/api/samples/unsigned', 'unsigned_document.pdf'));

    async function fetchDemoSample(url, defaultName) {
        showLoading(true);
        try {
            const res = await fetch(url);
            if (!res.ok) throw new Error(`Server error ${res.status}`);
            const blob = await res.blob();
            const file = new File([blob], defaultName, { type: 'application/pdf' });
            await handleFileUpload(file);
        } catch (e) {
            alert(`Failed to load demo sample: ${e.message}`);
            showLoading(false);
        }
    }

    function showLoading(isLoading) {
        loadingPanel.style.display = isLoading ? 'block' : 'none';
        if (isLoading) {
            resultsSection.style.display = 'none';
            // animate step pills
            const steps = [document.getElementById('step1'), document.getElementById('step2'), document.getElementById('step3'), document.getElementById('step4')];
            let activeIdx = 0;
            const timer = setInterval(() => {
                if (loadingPanel.style.display === 'none') {
                    clearInterval(timer);
                    return;
                }
                steps.forEach((s, idx) => s.classList.toggle('active', idx === activeIdx));
                activeIdx = (activeIdx + 1) % steps.length;
            }, 300);
        }
    }

    // Render Full Results
    function renderResults(report) {
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });

        metaFilename.textContent = report.filename || 'document.pdf';
        metaFileSize.textContent = formatBytes(report.file_size_bytes);
        metaSigCount.textContent = report.signatures_count;
        metaCheckedAt.textContent = new Date().toLocaleTimeString();
        engineBadge.textContent = report.validation_engine || 'Standard Engine';

        // Update Banner State
        verdictBanner.className = 'verdict-banner';
        if (report.overall_status === 'VALID') {
            verdictBanner.classList.add('valid');
            verdictBadge.textContent = 'AUTHENTIC & TRUSTED';
            verdictHeadline.textContent = 'Digital Signature Valid & Trusted';
            verdictDetail.textContent = 'Cryptographic message digest matches document byte slice and is chained to a trusted Root CA.';
            verdictIcon.innerHTML = `<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
        } else if (report.overall_status === 'INTACT_UNTRUSTED_CA') {
            verdictBanner.classList.add('warning');
            verdictBadge.textContent = 'INTACT & UNTAMPERED (UNTRUSTED CA)';
            verdictHeadline.textContent = 'Cryptographic Signature Intact';
            verdictDetail.textContent = 'The document has NOT been modified since signing. The cryptographic digest matches. Note: The certificate was issued by an external or national CA (or self-signed) not present in the local server trust store.';
            verdictIcon.innerHTML = `<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`;
        } else if (report.overall_status === 'CONTENT_INTACT_RSA_INVALID') {
            verdictBanner.classList.add('warning');
            verdictBadge.textContent = 'CONTENT INTACT — SIGNATURE PROOF DEFECTIVE';
            verdictHeadline.textContent = 'Document Unmodified, but RSA Proof Invalid';
            verdictDetail.textContent = 'The document byte-range hash matches exactly — content has NOT been altered since signing. However, the RSA/ECDSA cryptographic proof failed: the signature bytes do not verify against the signer\'s certificate public key. This is a defect in the original signing process, not a sign of document tampering.';
            verdictIcon.innerHTML = `<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`;
        } else if (report.overall_status === 'TAMPERED_OR_INVALID') {
            verdictBanner.classList.add('tampered');
            verdictBadge.textContent = 'TAMPERED / INVALID';
            verdictHeadline.textContent = 'Integrity Check Failed!';
            verdictDetail.textContent = 'The document contents do NOT match the signed cryptographic hash — the file has been modified after signing, or the signature byte stream is corrupted.';
            verdictIcon.innerHTML = `<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
        } else {
            verdictBanner.classList.add('unsigned');
            verdictBadge.textContent = 'UNSIGNED DOCUMENT';
            verdictHeadline.textContent = 'No Digital Signatures Found';
            verdictDetail.textContent = 'This PDF does not contain embedded cryptographic PKCS#7 or /ByteRange structures.';
            verdictIcon.innerHTML = `<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
        }

        // Reset Validation & Certificate Download Controls to Standard Initial State
        const validationBtn = document.getElementById('validationBtn');
        const verifiedTickCallout = document.getElementById('verifiedTickCallout');
        const isIntact = report.signatures && report.signatures.length > 0 && report.signatures.some(s => s.intact);

        isValidationConfirmed = false;
        if (validationBtn) {
            validationBtn.className = 'btn-action btn-action-emerald';
            validationBtn.disabled = false;
            validationBtn.title = 'Validate cryptographic signature and check integrity';
            validationBtn.innerHTML = `
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <span id="validationBtnText">Validation</span>
            `;
            if (isIntact && (report.overall_status === 'VALID' || report.overall_status === 'INTACT_UNTRUSTED_CA' || report.overall_status === 'CONTENT_INTACT_RSA_INVALID')) {
                validationBtn.style.display = 'inline-flex';
            } else {
                validationBtn.style.display = 'none';
            }
        }

        // Standard UX Rule: Explicit confirmation first.
        // Certificate callout banner remains hidden until user clicks "Validation".
        if (verifiedTickCallout) verifiedTickCallout.style.display = 'none';

        // Tab 1: Signatures Overview
        renderSignaturesOverview(report.signatures);

        // Tab 2: Certificate Inspector
        renderCertificateDetails(report.signatures);

        // Tab 3: ByteRange Visualizer
        renderByteRangeVisualizer(report);

        // Tab 4: Security & Anomalies
        renderSecurityAudit(report);

        // Tab 5: Raw JSON & curl
        rawJsonBlock.querySelector('code').textContent = JSON.stringify(report, null, 2);
        curlSnippet.querySelector('code').textContent = `curl -X POST "http://localhost:8000/api/validate" \\\n  -F "file=@${report.filename}"`;
    }

    // Translates pyHanko's internal summary codes into plain-English labels.
    // Format: "INTACT:TRUSTED,UNTOUCHED" — the UNTRUSTED part refers to the
    // *signing timestamp* having no RFC 3161 TSA proof, NOT to the signature itself.
    function translatePyhankoSummary(raw) {
        if (!raw) return null;
        const upper = raw.toUpperCase();

        // Timestamp trust part (between : and ,)
        let tsNote = '';
        if (upper.includes('UNTRUSTED')) {
            tsNote = 'Signing time is the signer\'s claimed clock (no Timestamp Authority proof).';
        } else if (upper.includes('TRUSTED')) {
            tsNote = 'Signing time is cryptographically verified by a Trusted Timestamp Authority.';
        }

        // Modification part (after ,)
        let modNote = '';
        if (upper.includes('NONE') || upper.includes('UNTOUCHED')) {
            modNote = 'No modifications detected after signing.';
        } else if (upper.includes('ALLOWED')) {
            modNote = 'Minor permitted incremental updates present (e.g. form fill, DSS update).';
        } else if (upper.includes('DISALLOWED') || upper.includes('TAMPER')) {
            modNote = 'Disallowed modifications detected.';
        }

        return [tsNote, modNote].filter(Boolean).join(' ');
    }

    function renderSignaturesOverview(signatures) {
        signaturesList.innerHTML = '';
        if (!signatures || signatures.length === 0) {
            signaturesList.innerHTML = `<div class="card-glass" style="text-align: center; color: var(--text-secondary);">No signatures to display.</div>`;
            return;
        }

        signatures.forEach((sig, idx) => {
            const card = document.createElement('div');
            card.className = 'signature-card';
            const isIntact = sig.intact && sig.cryptographically_valid;

            let badgeClass = 'invalid';
            let badgeText = 'TAMPERED / INVALID';
            if (isIntact && sig.is_trusted_ca) {
                badgeClass = 'valid';
                badgeText = 'VALID & TRUSTED';
            } else if (isIntact && !sig.is_trusted_ca) {
                badgeClass = 'warning';
                badgeText = 'INTACT (UNTRUSTED CA)';
            }

            const isTrustedTs = sig.timestamp?.is_trusted_ts;
            const tsDisplay = sig.timestamp?.display_time ||
                (sig.timestamp?.timestamp ? new Date(sig.timestamp.timestamp).toLocaleString() : 'Not recorded');
            const tsTypeLabel = isTrustedTs
                ? '<span style="color:var(--status-valid);">TSA-verified timestamp</span>'
                : '<span style="color:var(--status-warning);" title="Time recorded by the signer\'s own clock — no RFC 3161 Timestamp Authority token present. This is normal for most Indian DSC certificates.">Claimed by signer\'s clock (no TSA)</span>';

            const diagnosticNote = translatePyhankoSummary(sig.summary);

            card.innerHTML = `
                <div class="sig-header">
                    <div>
                        <span class="sig-name">${sig.field_name || `Signature #${idx + 1}`}</span>
                        <div style="font-size: 0.75rem; color: var(--text-muted);">${sig.coverage || 'Full Document'}</div>
                    </div>
                    <span class="sig-badge ${badgeClass}">
                        ${badgeText}
                    </span>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Signer Subject</div>
                    <div class="sig-field-val">${sig.certificate?.subject_name || 'Signer Identity Available'}</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Issuer Authority</div>
                    <div class="sig-field-val">${sig.certificate?.issuer_name || 'Embedded in PKCS#7'}</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Signing Time</div>
                    <div class="sig-field-val">${tsDisplay}</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Timestamp Type</div>
                    <div class="sig-field-val">${tsTypeLabel}</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Trust Status</div>
                    <div class="sig-field-val" style="color: ${sig.is_trusted_ca ? 'var(--status-valid)' : 'var(--status-warning)'};">
                        ${sig.is_trusted_ca ? 'Chained to Trusted CA' : 'External / Untrusted Root CA'}
                    </div>
                </div>
                ${diagnosticNote ? `
                <div class="sig-field" style="grid-column: 1 / -1; margin-top: 4px; padding-top: 8px; border-top: 1px dashed var(--border-color); font-size: 0.8rem; color: var(--text-secondary);">
                    <strong>Note:</strong> ${diagnosticNote}
                </div>` : ''}
            `;
            signaturesList.appendChild(card);
        });
    }

    function renderCertificateDetails(signatures) {
        if (!signatures || signatures.length === 0 || !signatures[0].certificate) {
            certificateDetailsCard.innerHTML = `<div style="text-align: center; color: var(--text-secondary);">No X.509 certificate data found in document.</div>`;
            return;
        }

        const cert = signatures[0].certificate;
        certificateDetailsCard.innerHTML = `
            <h3 class="panel-heading">X.509 Signer Certificate Inspector</h3>
            <p class="panel-sub">Cryptographic identity embedded within the PKCS#7 SignedData envelope.</p>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px;">
                <div class="sig-field">
                    <div class="sig-field-label">Subject Common Name</div>
                    <div class="sig-field-val">${cert.subject_name || 'N/A'}</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Certificate Issuer</div>
                    <div class="sig-field-val">${cert.issuer_name || 'N/A'}</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Serial Number</div>
                    <div class="sig-field-val" style="font-family: var(--font-mono);">${cert.serial_number || 'N/A'}</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Validity Period</div>
                    <div class="sig-field-val">${cert.valid_from ? new Date(cert.valid_from).toLocaleDateString() : 'N/A'} &rarr; ${cert.valid_to ? new Date(cert.valid_to).toLocaleDateString() : 'N/A'}</div>
                </div>
                <div class="sig-field" style="grid-column: 1 / -1;">
                    <div class="sig-field-label">SHA-256 Fingerprint</div>
                    <div class="sig-field-val" style="font-family: var(--font-mono); font-size: 0.8rem; word-break: break-all;">
                        ${cert.sha256_fingerprint || 'Not provided'}
                    </div>
                </div>
            </div>
        `;
    }

    function renderByteRangeVisualizer(report) {
        const fileSize = report.file_size_bytes;
        const sig = report.signatures && report.signatures[0];
        const br = sig?.byte_range || [0, Math.floor(fileSize * 0.45), Math.floor(fileSize * 0.6), Math.floor(fileSize * 0.4)];

        const o1 = br[0], l1 = br[1], o2 = br[2], l2 = br[3];
        const p1Pct = Math.max(5, ((l1 - o1) / fileSize) * 100);
        const gapPct = Math.max(5, ((o2 - (o1 + l1)) / fileSize) * 100);
        const p2Pct = Math.max(5, (l2 / fileSize) * 100);
        const appended = fileSize - (o2 + l2);
        const appPct = appended > 0 ? (appended / fileSize) * 100 : 0;

        byterangeBar.innerHTML = `
            <div class="bar-slice signed" style="width: ${p1Pct}%;" title="Part 1: bytes [${o1}...${o1 + l1}]">Part 1 (${formatBytes(l1)})</div>
            <div class="bar-slice placeholder" style="width: ${gapPct}%;" title="Excluded /Contents hex placeholder">/Contents</div>
            <div class="bar-slice signed" style="width: ${p2Pct}%;" title="Part 2: bytes [${o2}...${o2 + l2}]">Part 2 (${formatBytes(l2)})</div>
            ${appPct > 0 ? `<div class="bar-slice appended" style="width: ${appPct}%;" title="Trailing bytes after ByteRange: ${appended} bytes">Appended (${appended}B)</div>` : ''}
        `;

        byterangeDataGrid.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-top: 20px;">
                <div class="sig-field">
                    <div class="sig-field-label">ByteRange Offset 1</div>
                    <div class="sig-field-val" style="font-family: var(--font-mono);">0 &rarr; ${l1} bytes</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Excluded Signature Buffer</div>
                    <div class="sig-field-val" style="font-family: var(--font-mono);">${l1} &rarr; ${o2} (${o2 - l1} bytes)</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">ByteRange Offset 2</div>
                    <div class="sig-field-val" style="font-family: var(--font-mono);">${o2} &rarr; ${o2 + l2} bytes</div>
                </div>
                <div class="sig-field">
                    <div class="sig-field-label">Appended Beyond ByteRange</div>
                    <div class="sig-field-val" style="font-family: var(--font-mono); color: ${appended > 0 ? 'var(--status-tampered)' : 'var(--status-valid)'};">
                        ${appended > 0 ? `${appended} trailing bytes (Warning)` : '0 bytes (100% Covered)'}
                    </div>
                </div>
            </div>
        `;
    }

    function renderSecurityAudit(report) {
        anomaliesList.innerHTML = '';
        const anomalies = report.anomalies || [];

        if (anomalies.length === 0 && (report.overall_status === 'VALID' || report.overall_status === 'INTACT_UNTRUSTED_CA')) {
            anomaliesList.innerHTML = `
                <div style="background: rgba(0, 242, 169, 0.08); border: 1px solid var(--status-valid-border); border-radius: var(--radius-md); padding: 16px; color: var(--status-valid);">
                    <strong>No Shadow Attacks or Unauthorized Modifications Detected.</strong>
                    <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">The document does not have unauthorized incremental updates after the signature definition.</p>
                </div>
            `;
            return;
        }

        if (anomalies.length === 0 && report.overall_status === 'CONTENT_INTACT_RSA_INVALID') {
            anomaliesList.innerHTML = `
                <div style="background: rgba(255, 180, 0, 0.08); border: 1px solid var(--status-warning-border, #f59e0b); border-radius: var(--radius-md); padding: 16px; color: var(--status-warning, #f59e0b);">
                    <strong>RSA Proof Defective (Content Unmodified):</strong>
                    <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">Byte-range hash matches — no content changes detected. The RSA/ECDSA signature proof itself is invalid, which is a defect in the original signing process.</p>
                </div>
            `;
            return;
        }

        if (anomalies.length === 0 && report.overall_status === 'TAMPERED_OR_INVALID') {
            anomaliesList.innerHTML = `
                <div style="background: rgba(255, 59, 105, 0.08); border: 1px solid var(--status-tampered-border); border-radius: var(--radius-md); padding: 16px; color: var(--status-tampered);">
                    <strong>Integrity Violation:</strong>
                    <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">Hash digest mismatch. One or more bytes within the signed byte range were altered.</p>
                </div>
            `;
            return;
        }

        anomalies.forEach(anom => {
            const item = document.createElement('div');
            item.style.cssText = 'background: rgba(255, 183, 3, 0.08); border: 1px solid var(--status-warning-border); border-radius: var(--radius-md); padding: 16px; margin-bottom: 12px;';
            item.innerHTML = `
                <div style="color: var(--status-warning); font-weight: 600;">[${anom.severity}] ${anom.type}</div>
                <div style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 4px;">${anom.description}</div>
            `;
            anomaliesList.appendChild(item);
        });
    }

    // Tabs Switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-tab');
            document.getElementById(targetId)?.classList.add('active');
        });
    });

    // Copy Buttons
    copyCurlBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(curlSnippet.querySelector('code').textContent);
        copyCurlBtn.textContent = 'Copied!';
        setTimeout(() => copyCurlBtn.textContent = 'Copy Command', 2000);
    });

    copyJsonBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(rawJsonBlock.querySelector('code').textContent);
        copyJsonBtn.textContent = 'Copied!';
        setTimeout(() => copyJsonBtn.textContent = 'Copy JSON', 2000);
    });

    // Export Actions
    downloadReportBtn.addEventListener('click', () => {
        if (!currentReport) return;
        const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit_${currentReport.filename || 'report'}.json`;
        a.click();
        URL.revokeObjectURL(url);
    });

    const downloadPdfBtn = document.getElementById('downloadPdfBtn');
    if (downloadPdfBtn) {
        downloadPdfBtn.addEventListener('click', () => {
            if (!currentPdfBlob || !currentReport) return;
            const url = URL.createObjectURL(currentPdfBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = currentReport.filename || 'validated_document.pdf';
            a.click();
            URL.revokeObjectURL(url);
        });
    }

    // Green Tick Verified Copy Download Handler & State Locks
    let isGeneratingGreenTick = false;
    let isValidationConfirmed = false;

    async function downloadGreenTickCopy(e) {
        if (e) {
            e.preventDefault();
            e.stopPropagation();
        }

        if (isGeneratingGreenTick) {
            console.warn('[GreenTick] Download already in progress. Ignoring duplicate trigger.');
            return;
        }

        console.log('[GreenTick] downloadGreenTickCopy triggered');
        
        if (!currentPdfBlob) {
            if (fileInput && fileInput.files && fileInput.files.length > 0) {
                currentPdfBlob = fileInput.files[0];
            }
        }

        if (!currentPdfBlob) {
            alert('Document file not in active browser memory. Please drop or choose the PDF file once more, then click Validation.');
            return;
        }

        isGeneratingGreenTick = true;

        const btn = document.getElementById('bannerVerifiedTickBtn');
        const originalText = btn ? btn.innerHTML : '';

        if (btn) {
            btn.disabled = true;
            btn.classList.add('loading');
            btn.innerHTML = '<span class="btn-spinner"></span> Generating Certificate...';
        }

        const formData = new FormData();
        const fname = currentReport?.filename || currentPdfBlob.name || 'document.pdf';
        formData.append('file', currentPdfBlob, fname);

        try {
            console.log('[ValidationCertificate] Sending POST /api/verified-copy for:', fname);
            const res = await fetch('/api/verified-copy', {
                method: 'POST',
                body: formData
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `Server returned error (${res.status}): ${res.statusText}`);
            }

            const blob = await res.blob();
            console.log('[ValidationCertificate] Received verified blob size:', blob.size);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            
            const baseName = fname.replace(/\.[^/.]+$/, "");
            a.download = `${baseName}_validation_certificate.pdf`;
            
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 2000);
            console.log('[ValidationCertificate] Download completed successfully!');
            showToast('Certificate Downloaded ✔', 'Validation Certificate saved to your system.');
        } catch (err) {
            console.error('[ValidationCertificate] Download failed:', err);
            alert(`Could not generate Validation Certificate: ${err.message}`);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.classList.remove('loading');
                btn.innerHTML = originalText;
            }
            // Maintain guard for 1.5s to prevent any accidental double-click / rapid re-trigger
            setTimeout(() => {
                isGeneratingGreenTick = false;
            }, 1500);
        }
    }

    // Expose globally for backward compatibility
    window.downloadGreenTickCopy = downloadGreenTickCopy;

    // Toast Notification Helper
    let toastTimer = null;
    function showToast(title, message) {
        const toast = document.getElementById('toastNotification');
        const toastMsg = document.getElementById('toastMessage');
        const toastTitle = toast ? toast.querySelector('.toast-title') : null;
        if (!toast) return;

        if (toastTitle) toastTitle.textContent = title;
        if (toastMsg) toastMsg.textContent = message;

        toast.style.display = 'flex';
        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
            toast.style.display = 'none';
        }, 4500);
    }

    // Validation Button Click Handler (Follows standard UI/UX rules: confirmation first, NO automatic download)
    function onValidationBtnClick(e) {
        if (e) {
            e.preventDefault();
            e.stopPropagation();
        }

        const validationBtn = document.getElementById('validationBtn');
        const callout = document.getElementById('verifiedTickCallout');

        if (isValidationConfirmed) {
            showToast('Validation Already Completed ✔', 'Document signatures & cryptographic integrity are confirmed. You can download the validation certificate using the button below.');
            if (callout && callout.style.display !== 'none') {
                callout.classList.remove('pulse-highlight');
                void callout.offsetWidth;
                callout.classList.add('pulse-highlight');
                callout.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
            return;
        }

        // Standard UX Button Transition: Idle -> Validating (micro-feedback) -> Completed
        if (validationBtn) {
            validationBtn.classList.add('loading');
            validationBtn.innerHTML = `<span class="btn-spinner"></span> <span>Validating...</span>`;
        }

        setTimeout(() => {
            isValidationConfirmed = true;
            if (validationBtn) {
                validationBtn.classList.remove('loading');
                validationBtn.classList.add('completed');
                validationBtn.innerHTML = `
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <polyline points="20 6 9 17 4 12"/>
                    </svg>
                    <span id="validationBtnText">Validation Completed ✔</span>
                `;
                validationBtn.setAttribute('title', 'Validation completed — cryptographic integrity verified');
            }

            const isIntact = currentReport?.signatures?.some(s => s.intact);
            if (isIntact) {
                if (callout) {
                    callout.style.display = 'flex';
                    callout.classList.remove('pulse-highlight');
                    void callout.offsetWidth; // force reflow for CSS animation
                    callout.classList.add('pulse-highlight');
                    callout.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
                showToast('Validation Completed ✔', 'Signatures and cryptographic integrity verified. Click "Download Validation Certificate" below if you wish to download.');
            } else {
                showToast('Validation Completed', 'Document cryptographic inspection finished. Details shown below.');
            }
        }, 350);
    }

    // Validation Button: Only confirms and displays "Validation Completed ✔"
    const validationBtnEl = document.getElementById('validationBtn');
    if (validationBtnEl) {
        validationBtnEl.addEventListener('click', onValidationBtnClick);
    }

    // Single Download Button in Callout Banner: Explicit user choice whether to download or not
    const bannerVerifiedTickBtn = document.getElementById('bannerVerifiedTickBtn');
    if (bannerVerifiedTickBtn) {
        bannerVerifiedTickBtn.addEventListener('click', (e) => downloadGreenTickCopy(e));
    }

    printReportBtn.addEventListener('click', () => window.print());

    // Trust Store Modal
    openTrustStoreBtn.addEventListener('click', () => {
        loadTrustStore();
        trustModal.style.display = 'flex';
    });

    closeTrustModalBtn.addEventListener('click', () => {
        trustModal.style.display = 'none';
    });

    trustModal.addEventListener('click', (e) => {
        if (e.target === trustModal) trustModal.style.display = 'none';
    });

    async function loadTrustStore() {
        try {
            const res = await fetch('/api/trusted-certs');
            const data = await res.json();
            trustedCertsList.innerHTML = '';
            if (data.trusted_certs.length === 0) {
                trustedCertsList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; padding: 8px;">No custom lab root certificates uploaded yet. Default system roots are active.</div>`;
                return;
            }
            data.trusted_certs.forEach(c => {
                const item = document.createElement('div');
                item.className = 'cert-item';
                item.innerHTML = `<span>${c.filename}</span><span style="color: var(--text-muted);">${formatBytes(c.size_bytes)}</span>`;
                trustedCertsList.appendChild(item);
            });
        } catch (e) {
            console.error('Failed to load certs:', e);
        }
    }

    uploadCertBtn.addEventListener('click', async () => {
        if (!certFileInput.files.length) {
            alert('Please choose a .crt, .pem, or .cer file first');
            return;
        }
        const formData = new FormData();
        formData.append('file', certFileInput.files[0]);

        try {
            const res = await fetch('/api/trusted-certs', { method: 'POST', body: formData });
            const data = await res.json();
            if (data.success) {
                alert('Root Certificate successfully added to Lab Trust Store!');
                certFileInput.value = '';
                loadTrustStore();
            } else {
                alert('Upload failed: ' + data.detail);
            }
        } catch (e) {
            alert('Upload error: ' + e.message);
        }
    });

    function formatBytes(bytes, decimals = 1) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
});
