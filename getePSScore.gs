function getePSScore(cveId) {
  var url = "https://api.first.org/data/v1/epss?cve=" + cveId;

// Set options
  var options = {
    muteHttpExceptions: true,
  };

  var response = UrlFetchApp.fetch(url, options);
  var json = JSON.parse(response.getContentText());
  
  // Error checking or if there is no ePSS score
  if (json.data.length == 0 || 
      !json.data[0].hasOwnProperty('epss')) {
    return 'N/D';
  }
  
  // return the base score
  var rawepssScore = json.data[0].epss;
  var epssScore = (rawepssScore * 100).toFixed(2);
  return epssScore;
}
