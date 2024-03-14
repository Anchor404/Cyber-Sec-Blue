#include <chrono>
#include <iomanip>
#include <iostream>
#include <pcap.h>

void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  // Increment packet counter
  int *counter = reinterpret_cast<int *>(userData);
  (*counter)++;

  // Get current time
  auto now = std::chrono::system_clock::now();
  auto now_c = std::chrono::system_clock::to_time_t(now);

  // Print the output
  std::cout << "{Time: " << std::put_time(std::localtime(&now_c), "%T")
            << ",   Packets Captured: " << *counter << "} \n";
}

int main() {
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  // Open device for live capture
  dev = pcap_lookupdev(errbuf);
  if (dev == nullptr) {
    std::cerr << "Couldn't find default device: " << errbuf << std::endl;
    return 1;
  }

  // Open device
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
    return 1;
  }

  int packet_count = 0;

  // Start timer
  auto start = std::chrono::steady_clock::now();

  // Capture packets indefinitely
  pcap_loop(handle, -1, packet_handler,
            reinterpret_cast<u_char *>(&packet_count));

  // Close the handle
  pcap_close(handle);

  return 0;
}
