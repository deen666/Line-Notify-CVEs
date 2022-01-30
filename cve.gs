function CVE() {
  
  var token = "abcdefg123456"; // Your Token 
  
  var total =[];

  var fetchAPI = UrlFetchApp.fetch("https://cve.circl.lu/api/last");
  var json = JSON.parse(fetchAPI.getContentText());

  for (var i = 1; i < 30; i++) {
    if (json[i].cvss >= 6) {     
        total[i+1] = json[i].id;
        total[i+2] = json[i].summary;
        total[i+6] = json[i].cvss;
        total[i+3] = json[i].references;
        total[i+4] = json[i].Modified;
        total[i+5] = json[i].assigner;
    }
  

  // Convert UTC to GMT
  var timeZone = "GMT+7"  
  var format = "dd-MM-YYYY hh:mm:ss"
  var moment = new Date(total[i+4]);
  var formattedDate = Utilities.formatDate(moment, timeZone, format)
  var formData =
       {
         'message' : "Update CVEs @ "
         + "\n" + " -----"
         + "\n" + "" + formattedDate + ""
         + "\n" + " "
         + "\n" + "" + total[i+2] + ""
         + "\n" + " "
         + "\n" + "CVSS: " + total[i+6] + " "
         + "\n" + " "
         + "\n" + "summary: " + total[i+2] + " "
         + "\n" + " "
         + "\n" + "references: " + total[i+3] + " "
         + "\n" + " "
         + "\n" + "assigner: " + total[i+5] + " "
         + "\n" + " "
       }

  var options =
   {
     "method"  : "post",
     "payload" : formData,
     "headers" : {"Authorization" : "Bearer "+ token}
   };
  if (total[i+6] >= 6) { 
    UrlFetchApp.fetch("https://notify-api.line.me/api/notify",options);
  }
  }
}


