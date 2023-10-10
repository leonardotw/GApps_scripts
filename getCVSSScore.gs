function getCVSSScore(cveId) {
  var url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveId;

// Set options and NIST API Key https://nvd.nist.gov/developers/request-an-api-key
  var options = {
    muteHttpExceptions: true,
    headers: {
      'apiKey': 'xxxxxx-xxxx-xxxx-xxxx-xxxxxxx'
    }
  };

  var response = UrlFetchApp.fetch(url, options);
  var json = JSON.parse(response.getContentText());
  
  // Error checking or if there is no baseMetricV3 score
  if (json.vulnerabilities.length == 0 || 
      !json.vulnerabilities[0].hasOwnProperty('cve') || 
      !json.vulnerabilities[0].cve.hasOwnProperty('metrics') || 
      !json.vulnerabilities[0].cve.metrics.hasOwnProperty('cvssMetricV31') || 
      !json.vulnerabilities[0].cve.metrics.cvssMetricV31[0].hasOwnProperty('cvssData') ||
      !json.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.hasOwnProperty('baseScore')) {
    return 'N/D';
  }
  
  // return the base score
  var cvssScore = json.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore;
  return cvssScore;
}
