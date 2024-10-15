$(document).ready(function() {
  // Fetch and update the count of device entries logged
  $.get("/api/device_entries_logged", function(data) {
    $("#devices_logged").text(data.device_entries_logged);
  });

  // Fetch and update the count of active devices
  $.get("/api/no_of_devices_active", function(data) {
    $("#active_devices").text(data.no_of_devices_active);
  });
});
