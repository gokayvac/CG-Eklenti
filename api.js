class VirusTotalAPI {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://www.virustotal.com/api/v3';
  }

  setApiKey(apiKey) { this.apiKey = apiKey; }

  async urlInfo({ id }) {
    try {
      return await this._makeRequest(`/urls/${encodeURIComponent(decodeURIComponent(id))}`);
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async _makeRequest(endpoint) {
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        method: 'GET', 
        headers: { 'x-apikey': this.apiKey, 'Content-Type': 'application/json' }
      });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return await response.json();
    } catch (error) {
      console.error('API isteği başarısız:', error);
      throw error;
    }
  }

  static extractIdFromUrl(url) {
    try {
      const parts = new URL(url).pathname.split('/');
      const type = url.includes('/url/') ? 'url' : url.includes('/file/') ? 'file' : null;
      return type ? parts[parts.indexOf(type) + 1] || null : null;
    } catch (error) {
      console.error(error);
      return null;
    }
  }
}

const virustotal = new VirusTotalAPI('');
export default virustotal;