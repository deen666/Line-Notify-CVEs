function CVE() {
  
  var token = "abcdefg123456"; // Your Token 
  
  var total =[];

  var fetchAPI = UrlFetchApp.fetch("https://cve.circl.lu/api/last");
  var json = JSON.parse(fetchAPI.getContentText());
  total[1] = json[0].id;
  total[2] = json[0].summary;
  total[6] = json[0].cvss;
  total[3] = json[0].references;
  total[4] = json[0].Modified;
  total[5] = json[0].assigner;

  // Convert UTC to GMT
  var timeZone = "GMT+7"  
  var format = "dd-MM-YYYY hh:mm:ss"
  var moment = new Date(total[4]);
  var formattedDate = Utilities.formatDate(moment, timeZone, format)
 
  var formData =
       {
         'message' : "Update CVEs @ "
         + "\n" + " -----"
         + "\n" + "" + formattedDate + ""
         + "\n" + "" + total[1] + " / CVSS: " + total[6] + " "
         + "\n" + "summary: " + total[2] + " "
         + "\n" + "references: " + total[3] + " "
         + "\n" + "assigner: " + total[5] + " "
         + "\n" + " -----"
       }

  var options =
   {
     "method"  : "post",
     "payload" : formData,
     "headers" : {"Authorization" : "Bearer "+ token}
   };
 UrlFetchApp.fetch("https://notify-api.line.me/api/notify",options);
}
