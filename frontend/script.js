async function uploadFile() {
  const input = document.getElementById("pcapFile");
  const output = document.getElementById("output");

  if (!input.files.length) {
    alert("Please select a pcap file first.");
    return;
  }

  const formData = new FormData();
  formData.append("file", input.files[0]);

  output.innerHTML = "Analyzing...";

  try {
    const response = await fetch("http://127.0.0.1:5000/upload", {
    method: "POST",
    body: formData
    });

    const data = await response.json();
    renderResults(data);
  } catch (err) {
    output.innerHTML = "Error: " + err;
  }
}

function renderResults(data) {
  const output = document.getElementById("output");
  output.innerHTML = `<p>Total packets: ${data.total_packets}</p>`;

  let table = "<table border='1'><tr><th>Src IP</th><th>Dst IP</th><th>Protocol</th><th>Src Port</th><th>Dst Port</th><th>Length</th><th>Src MAC</th><th>Dst MAC</th></tr>";
  data.packets.forEach(p => {
    table += `<tr><td>${p.src_ip}</td><td>${p.dst_ip}</td><td>${p.protocol}</td><td>${p.src_port}</td><td>${p.dst_port}</td><td>${p.length}</td><td>${p.src_mac}</td><td>${p.dst_mac}</td></tr>`;
  });
  table += "</table>";
  output.innerHTML += table;
}