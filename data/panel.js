function reportOnPanel(report) {
  document.getElementById("report-name").textContent = report.name;
  if (report.verified) {
    document.getElementById("report-scheme").textContent = report.scheme;
    document.getElementById("report-host").textContent = report.host;
    document.getElementById("report-domain").style.display = "inline";
    document.getElementById("report-status").textContent = "Verified by ";
  } else {
    document.getElementById("report-domain").style.display = "none";
    document.getElementById("report-status").textContent = "Not verified";
  }
  document.getElementById("secure-report").style.display = "block";
}

self.port.on("secure-content-add-report", function (report_json) {
  var report = JSON.parse(report_json);
  reportOnPanel(report);
});

self.port.on("secure-content-rem-report", function (report_json) {
  var report = JSON.parse(report_json);
  document.location = "./panel.js";
  document.getElementById("secure-report").style.display = "none";
});
