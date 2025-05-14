const DEBUG = true;
function logDebug(...args) { DEBUG && console.log('[VT-Debug]', ...args); }
function logError(...args) { console.error('[VT-Error]', ...args); }
function isVirusTotalLink(url) { return url.includes('virustotal.com'); }

function createNotification() {
  const notification = document.createElement('div');
  notification.className = 'vt-notification';
  notification.innerHTML = 'VT sonuçlarını görmek için tıklayın!';
  notification.addEventListener('click', () => foundVirusTotalLinks.length > 0 && showVirusTotalModal(foundVirusTotalLinks[0]));
  document.body.appendChild(notification);
  setTimeout(() => {
    document.body.contains(notification) && (notification.classList.add('vt-fade-out'), setTimeout(() => document.body.contains(notification) && document.body.removeChild(notification), 500));
  }, 5000);
}

async function fetchVirusTotalData(url) {
  return new Promise((resolve, reject) => chrome.runtime.sendMessage({ action: 'getVirusTotalData', url }, response => response?.success ? resolve(response.data) : reject(response?.error || 'Failed to fetch VirusTotal data')));
}

async function showVirusTotalModal(vtUrl) {
  if (!vtUrl) { logError('No VirusTotal URL provided'); return; }
  logDebug('Opening modal for URL:', vtUrl);
  try {
    const { modalContainer, modal, sidebar, sidebarNav, contentBody } = createModalStructure('VirusTotal Analysis');
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'vt-loading-container';
    loadingDiv.innerHTML = '<div class="vt-spinner"></div><p>Sonuçlar Yükleniyor...</p>';
    contentBody.appendChild(loadingDiv);
    document.body.appendChild(modalContainer);
    try {
      const vtData = await fetchVirusTotalData(vtUrl);
      const navItems = [
        { label: 'Summary', content: createSummaryContent(vtData.data, vtData.data.attributes) },
        { label: 'Detections', content: createDetectionContent(vtData.data.attributes) }
      ];
      const details = createDetailsContent(vtData.data, vtData.data.attributes);
      details && navItems.push({ label: 'Details', content: details });
      navItems.push({ label: 'Raw Data', content: createRawDataContent(vtData) });
      contentBody.innerHTML = '';
      createSidebarNavigation(sidebarNav, navItems, contentBody);
    } catch (error) { showErrorInModal(contentBody, error.message, vtUrl); }
  } catch (error) { logError('Error creating modal:', error); }
}

function createModalStructure(title) {
  const modalContainer = document.createElement('div');
  modalContainer.className = 'vt-modal-container';
  const modal = document.createElement('div');
  modal.className = 'vt-modal';
  const sidebar = document.createElement('div');
  sidebar.className = 'vt-sidebar';
  sidebar.innerHTML = `<div class="vt-sidebar-header"><div class="vt-sidebar-header-icon">VT</div><div class="vt-sidebar-header-title">CheatGlobal</div></div><div class="vt-sidebar-nav"></div><div class="vt-sidebar-footer">Created by <a href="https://github.com/gokayvac" target="_blank">gokaysevinc</a></div>`;
  const sidebarNav = sidebar.querySelector('.vt-sidebar-nav');
  const contentArea = document.createElement('div');
  contentArea.className = 'vt-content-area';
  contentArea.innerHTML = `<div class="vt-content-header"><h2 class="vt-content-title">${title}</h2><button class="vt-content-close">&times;</button></div><div class="vt-content-body"></div>`;
  const contentBody = contentArea.querySelector('.vt-content-body');
  modal.appendChild(sidebar);
  modal.appendChild(contentArea);
  modalContainer.appendChild(modal);
  modalContainer.querySelector('.vt-content-close').addEventListener('click', () => document.body.contains(modalContainer) && document.body.removeChild(modalContainer));
  modalContainer.addEventListener('click', e => e.target === modalContainer && document.body.contains(modalContainer) && document.body.removeChild(modalContainer));
  return { modalContainer, modal, sidebar, sidebarNav, contentBody };
}

function createSidebarNavigation(sidebarNav, navItems, contentBody) {
  if (!sidebarNav) return;
  const iconMap = {
    'Summary': '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>',
    'Detections': '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><line x1="22" y1="10" x2="2" y2="10"></line></svg>',
    'Details': '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>',
    'Raw Data': '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>'
  };
  const analysisSection = document.createElement('div');
  analysisSection.className = 'vt-nav-section';
  analysisSection.innerHTML = '<div class="vt-nav-section-title">Analysis</div>';
  navItems.forEach((navItem, index) => {
    const item = document.createElement('button');
    item.className = `vt-nav-item ${index === 0 ? 'active' : ''}`;
    item.innerHTML = `<span class="vt-nav-item-icon">${iconMap[navItem.label] || ''}</span><span class="vt-nav-item-label">${navItem.label}</span>`;
    item.addEventListener('click', () => {
      document.querySelectorAll('.vt-nav-item').forEach(el => el.classList.remove('active'));
      item.classList.add('active');
      showContentItem(contentBody, navItem.content);
    });
    analysisSection.appendChild(item);
    index === 0 && showContentItem(contentBody, navItem.content);
  });
  sidebarNav.appendChild(analysisSection);
}

function showContentItem(contentBody, content) { contentBody.innerHTML = ''; content && contentBody.appendChild(content); }

function formatJsonForDisplay(data) {
  return JSON.stringify(data, null, 2).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
      let cls = 'vt-json-number';
      if (/^"/.test(match)) cls = /:$/.test(match) ? 'vt-json-key' : 'vt-json-string';
      else if (/true|false/.test(match)) cls = 'vt-json-boolean';
      else if (/null/.test(match)) cls = 'vt-json-null';
      return `<span class="${cls}">${match}</span>`;
    });
}

function createSummaryContent(data, attributes) {
  const summarySection = document.createElement('div');
  summarySection.className = 'vt-section vt-summary-section';
  summarySection.innerHTML = `<div class="vt-type-display">${data.type === 'url' ? `URL: ${attributes.url || 'Unknown URL'}` : data.type === 'file' ? `File: ${attributes.meaningful_name || attributes.name || data.id || 'Unknown File'}` : `Resource: ${data.id || 'Unknown'}`}</div>`;
  attributes.last_analysis_date && (summarySection.innerHTML += `<div class="vt-date">Last analyzed: ${new Date(attributes.last_analysis_date * 1000).toLocaleString()}</div>`);

  if (attributes.last_analysis_stats) {
    const stats = attributes.last_analysis_stats;
    const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
    const malicious = stats.malicious || 0, suspicious = stats.suspicious || 0, harmless = stats.harmless || 0, undetected = stats.undetected || 0;
    const threatScore = (malicious + suspicious) / totalEngines;
    const threatLevel = threatScore > 0.5 ? ['high', '#e74c3c'] : threatScore > 0.2 ? ['medium', '#f39c12'] : threatScore > 0 ? ['low', '#3498db'] : ['safe', '#2ecc71'];

    summarySection.innerHTML += `
      <div class="vt-threat-indicator"><span class="vt-threat-level" style="background-color:${threatLevel[1]}">${threatLevel[0].toUpperCase()}</span><div class="vt-threat-text">Threat Level</div></div>
      <div class="vt-stats"><div class="vt-stats-title">Detection Results</div><div class="vt-stats-chart">
        <div class="vt-stat-item vt-stat-malicious" style="width:${(malicious/totalEngines)*100}%"><span>${malicious}</span></div>
        <div class="vt-stat-item vt-stat-suspicious" style="width:${(suspicious/totalEngines)*100}%"><span>${suspicious}</span></div>
        <div class="vt-stat-item vt-stat-harmless" style="width:${(harmless/totalEngines)*100}%"><span>${harmless}</span></div>
        <div class="vt-stat-item vt-stat-undetected" style="width:${(undetected/totalEngines)*100}%"><span>${undetected}</span></div>
      </div><div class="vt-stats-legend">
        <div class="vt-legend-item"><span class="vt-legend-color vt-color-malicious"></span> Malicious</div>
        <div class="vt-legend-item"><span class="vt-legend-color vt-color-suspicious"></span> Suspicious</div>
        <div class="vt-legend-item"><span class="vt-legend-color vt-color-harmless"></span> Harmless</div>
        <div class="vt-legend-item"><span class="vt-legend-color vt-color-undetected"></span> Undetected</div>
      </div></div>`;
  }

  if (data.type === 'file' && attributes) {
    attributes.type_description && (summarySection.innerHTML += `<div class="vt-file-info"><strong>File Type:</strong> ${attributes.type_description}</div>`);
    attributes.size && (summarySection.innerHTML += `<div class="vt-file-info"><strong>Size:</strong> ${formatFileSize(attributes.size)}</div>`);
    data.id && (summarySection.innerHTML += `<div class="vt-file-info vt-hash"><strong>SHA-256:</strong> ${data.id}</div>`);
  }

  return summarySection;
}

function createDetectionContent(attributes) {
  const resultsSection = document.createElement('div');
  resultsSection.className = 'vt-section vt-results-section';
  if (!attributes.last_analysis_results || !Object.keys(attributes.last_analysis_results).length) return resultsSection.innerHTML = '<p style="color:var(--text-secondary);text-align:center;padding:var(--space-2xl)">No detection data available.</p>', resultsSection;
  resultsSection.innerHTML = '<h3>Security Vendors Analysis</h3><table class="vt-results-table"><thead><tr><th>Vendor</th><th>Result</th><th>Category</th></tr></thead><tbody></tbody></table>';
  Object.entries(attributes.last_analysis_results).sort((a,b) => ['malicious','suspicious','harmless','undetected'].indexOf(a[1].category) - ['malicious','suspicious','harmless','undetected'].indexOf(b[1].category))
    .forEach(([engine, result]) => resultsSection.querySelector('tbody').innerHTML += `<tr class="vt-result-${result.category}"><td>${engine}</td><td>${result.result || 'N/A'}</td><td>${result.category || 'unknown'}</td></tr>`);
  return resultsSection;
}

function createDetailsContent(data, attributes) {
  const detailsSection = document.createElement('div');
  detailsSection.className = 'vt-section vt-details-section';
  detailsSection.innerHTML = '<h3>Detailed Information</h3><div class="vt-metadata-list"></div>';
  const addMetadata = (label, value) => value != null && (detailsSection.querySelector('.vt-metadata-list').innerHTML += `<div class="vt-metadata-item"><div class="vt-metadata-label">${label}</div><div class="vt-metadata-value">${value}</div></div>`);
  data.type === 'file' ? (
    addMetadata('File Type', attributes.type_description || attributes.type_tag || 'Unknown'),
    addMetadata('File Size', attributes.size ? formatFileSize(attributes.size) : 'Unknown'),
    attributes.md5 && addMetadata('MD5', attributes.md5),
    attributes.sha1 && addMetadata('SHA-1', attributes.sha1),
    attributes.sha256 && addMetadata('SHA-256', attributes.sha256)
  ) : data.type === 'url' && (
    addMetadata('URL', attributes.url || data.id || 'Unknown'),
    attributes.categories && addMetadata('Categories', Object.entries(attributes.categories).map(([k,v]) => `${k}: ${v}`).join(', ')),
    attributes.last_final_url && attributes.last_final_url !== attributes.url && addMetadata('Redirects To', attributes.last_final_url)
  );
  attributes.reputation !== undefined && addMetadata('Reputation', `${attributes.reputation < -20 ? 'Very Poor' : attributes.reputation < 0 ? 'Poor' : attributes.reputation > 20 ? 'Very Good' : attributes.reputation > 0 ? 'Good' : 'Neutral'} (${attributes.reputation})`);
  attributes.last_analysis_date && addMetadata('Last Analysis', new Date(attributes.last_analysis_date * 1000).toLocaleString());
  return detailsSection;
}

function createRawDataContent(vtData) {
  const rawDataSection = document.createElement('div');
  rawDataSection.className = 'vt-section vt-raw-data-section';
  rawDataSection.innerHTML = '<h3>Raw API Response</h3><div class="vt-json-view">' + formatJsonForDisplay(vtData) + '</div>';
  return rawDataSection;
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showErrorInModal(contentBody, errorMessage, vtUrl) {
  contentBody.innerHTML = `<div class="vt-error-container"><div class="vt-error-icon">!</div><p class="vt-error-message">${errorMessage || 'An error occurred while retrieving VirusTotal data'}</p><p class="vt-error-info">This may be due to API limitations or lack of an API key.</p><button class="vt-button vt-button-primary">Open in VirusTotal</button></div>`;
  contentBody.querySelector('.vt-button').addEventListener('click', () => window.open(vtUrl, '_blank'));
}

let foundVirusTotalLinks = [], notificationShown = false;

function scanForVirusTotalLinks() {
  foundVirusTotalLinks = [];
  document.querySelectorAll('a').forEach(link => {
    if (link.href && isVirusTotalLink(link.href)) {
      foundVirusTotalLinks.push(link.href);
      link.addEventListener('click', e => { e.preventDefault(); showVirusTotalModal(link.href); });
    }
  });
  foundVirusTotalLinks.length > 0 && !notificationShown && (createNotification(), notificationShown = true);
}

scanForVirusTotalLinks();
new MutationObserver(scanForVirusTotalLinks).observe(document.body, { childList: true, subtree: true });