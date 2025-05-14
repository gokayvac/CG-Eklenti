const VT_API_KEY = 'ab7a7f5c701df15a1464fdfe63bc88c5a42fdaae68b6c2e055f52c504ac6b10a';
const VT_API_BASE = 'https://www.virustotal.com/api/v3';

function extractResourceInfo(url) {
  try {
    const vtUrl = new URL(url);
    if (vtUrl.hostname.includes('virustotal.com')) {
      const pathParts = vtUrl.pathname.split('/').filter(part => part);
      if (pathParts.length >= 2) {
        const resourceType = pathParts[0];
        if (resourceType === 'gui' && pathParts.length >= 3) {
          return { type: pathParts[1], id: pathParts[2] };
        } else if (resourceType === 'file' || resourceType === 'url') {
          return { type: resourceType, id: pathParts[1] };
        }
      }
    }
    for (const param of ['resource', 'file', 'url']) {
      if (vtUrl.searchParams.has(param)) {
        return { type: param === 'resource' ? 'file' : param, id: vtUrl.searchParams.get(param) };
      }
    }
    if (vtUrl.hash.length > 1) {
      const hashValue = vtUrl.hash.substring(1);
      return { type: hashValue.length >= 32 ? 'file' : 'url', id: hashValue };
    }
    throw new Error('Could not identify resource from URL');
  } catch (error) {
    console.error('Error extracting resource:', error);
    return null;
  }
}

async function fetchVirusTotalDataV3(resourceInfo) {
  try {
    const { type, id } = resourceInfo;
    const endpoint = type === 'file' ? 
      `${VT_API_BASE}/files/${id}` :
      `${VT_API_BASE}/urls/${id.startsWith('http') || id.includes('.') ? btoa(id).replace(/=/g, '') : id}`;
    
    const response = await fetch(endpoint, {
      headers: { 'x-apikey': VT_API_KEY, 'Content-Type': 'application/json' }
    });
    if (!response.ok) throw new Error(`API request failed: ${await response.text()}`);
    return await response.json();
  } catch (error) {
    console.error('Error fetching data:', error);
    throw error;
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getVirusTotalData') {
    (async () => {
      try {
        const resourceInfo = extractResourceInfo(message.url);
        if (!resourceInfo) throw new Error('Invalid URL');
        const data = await fetchVirusTotalDataV3(resourceInfo);
        sendResponse({ success: true, data });
      } catch (error) {
        sendResponse({ success: false, error: error.message });
      }
    })();
    return true;
  }
});