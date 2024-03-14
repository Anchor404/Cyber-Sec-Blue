// SBOM
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <pcap.h>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

// Global variables for packet count and total bytes
int packet_count = 0;
long long total_bytes = 0;

// Mutex for synchronization
std::mutex mtx;

// Function to execute a shell command and return the output
std::string exec(const char *cmd) {
  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

// Function to remove newline characters from a string
void removeNewlines(std::string &str) {
  str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
}

// Function to prompt the user for filtering criteria selection
std::string getUserFilteringCriteria() {
  std::string filteringCriteria;

  // Prompt the user for filtering criteria selection
  std::cout << "Filtering Criteria Selection:" << std::endl;
  std::cout << "1. Filter based on your IP address" << std::endl;
  std::cout << "2. Filter based on network details" << std::endl;
  std::cout << "3. Filter based on specific ports" << std::endl;
  std::cout << "Enter your choice (1, 2, or 3): ";
  std::getline(std::cin, filteringCriteria);

  // Validate user input
  while (filteringCriteria != "1" && filteringCriteria != "2" &&
         filteringCriteria != "3") {
    std::cout << "Invalid choice. Please enter 1, 2, or 3: ";
    std::getline(std::cin, filteringCriteria);
  }

  return filteringCriteria;
}

// Function to prompt the user for monitoring duration
std::string getUserMonitoringDuration() {
  std::string monitoringDuration;

  // Prompt the user for monitoring duration selection
  std::cout << "Monitoring Duration Selection:" << std::endl;
  std::cout << "1. Specify duration in minutes" << std::endl;
  std::cout << "2. Specify duration in hours" << std::endl;
  std::cout << "Enter your choice (1 or 2): ";
  std::getline(std::cin, monitoringDuration);

  // Validate user input
  while (monitoringDuration != "1" && monitoringDuration != "2") {
    std::cout << "Invalid choice. Please enter 1 or 2: ";
    std::getline(std::cin, monitoringDuration);
  }

  return monitoringDuration;
}

// Class to handle network-related functionalities
class NetworkHandler {
public:
  // Function to get the user's IP address
  static std::string getIPAddress() {
    std::string ipAddr = exec("ip route get 1 | awk '{print $NF;exit}'");
    removeNewlines(ipAddr);
    return ipAddr;
  }

  // Function to get the network details
  static std::string getNetworkDetails() {
    std::string networkDetails =
        exec("ip route | grep default | awk '{print $3}'");
    removeNewlines(networkDetails);
    return networkDetails;
  }

  // Function to get the currently used ports on the device
  static std::vector<int> getUsedPorts() {
    std::vector<int> usedPorts;
    std::string netstatOutput = exec("netstat -tuln");
    std::istringstream iss(netstatOutput);
    std::string line;
    while (std::getline(iss, line)) {
      if (line.find("LISTEN") != std::string::npos) {
        size_t pos = line.find_last_of(":");
        if (pos != std::string::npos) {
          int port = std::stoi(line.substr(pos + 1));
          usedPorts.push_back(port);
        }
      }
    }
    return usedPorts;
  }
};

// Class to handle bandwidth monitoring
class BandwidthMonitor {
public:
  // Function to calculate bandwidth
  static void monitorBandwidth() {
    // Placeholder for bandwidth monitoring logic
  }
};

// Packet handler function
void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  // Increment packet counter
  mtx.lock();
  packet_count++;
  mtx.unlock();

  // Increment total bytes
  mtx.lock();
  total_bytes += pkthdr->len;
  mtx.unlock();
}

int main() {

  // Display user information
  std::cout << "User Information:" << std::endl;
  std::cout << "IP address: " << NetworkHandler::getIPAddress() << std::endl;
  std::cout << "Network details: " << NetworkHandler::getNetworkDetails()
            << std::endl;
  std::cout << "Used ports: ";
  std::vector<int> ports = NetworkHandler::getUsedPorts();
  for (int port : ports) {
    std::cout << port << " ";
  }
  std::cout << std::endl;

  // Get user filtering criteria selection
  std::string filteringCriteria = getUserFilteringCriteria();

  // Process user's choice
  if (filteringCriteria == "1") {
    std::cout << "Filtering based on your IP address" << std::endl;
    // Implement filtering based on user's IP address
  } else if (filteringCriteria == "2") {
    std::cout << "Filtering based on network details" << std::endl;
    // Implement filtering based on network details
  } else if (filteringCriteria == "3") {
    std::cout << "Filtering based on specific ports" << std::endl;
    // Implement filtering based on specific ports
  }

  // Get user monitoring duration selection
  std::string monitoringDuration = getUserMonitoringDuration();

  // Process user's choice
  if (monitoringDuration == "1") {
    std::cout << "Monitoring duration specified in minutes" << std::endl;
    // Implement monitoring for specified duration in minutes
  } else if (monitoringDuration == "2") {
    std::cout << "Monitoring duration specified in hours" << std::endl;
    // Implement monitoring for specified duration in hours
  }

  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  // Open device for live capture
  dev = pcap_lookupdev(errbuf);
  if (dev == nullptr) {
    cerr << "Couldn't find default device: " << errbuf << endl;
    return 1;
  }

  // Open device
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    cerr << "Couldn't open device " << dev << ": " << errbuf << endl;
    return 1;
  }

  // Start packet capture
  pcap_loop(handle, -1, packet_handler, nullptr);

  // Close the handle
  pcap_close(handle);

  return 0;
}
