logFile= "sample.log"
log_lines=[]
with open(logFile,"r") as file :
    for line in file:
        # print(line.strip()) 
         log_lines.append(line.strip())  # to store eachline
       



ip_counts = {} # to store count of ip adress

for line in log_lines:
    
    ip = "" # for ip adress
    for char in line:
        if char == " ":
            break
        ip += char # ip adress is succesfully extracted here.

    # Count the IP address
    if ip in ip_counts:
        ip_counts[ip] += 1
    else:
        ip_counts[ip] = 1


print("\nIP Address    |     Request Count\n")  #Heading
for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):

    print(f"{ip:<25}{count}")


print("IP Address           Request Count")  # Heading
for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:<20}{count}")


most_frequent_ip = None
highest_count = 0

for ip, count in ip_counts.items():
    if count > highest_count:
        highest_count = count
        most_frequent_ip = ip

print("\nMost Frequent Request:")
print(f"IP Address: {most_frequent_ip}")
print(f"Request Count: {highest_count}")


endpoint_counts = {}  

for line in log_lines:
    if "GET" in line or "POST" in line:  # Check HTTP methods
        parts = line.split()
        if len(parts) > 6:  
            endpoint = parts[6]  # Assuming the endpoint is at index 6
            if endpoint in endpoint_counts:
                endpoint_counts[endpoint] += 1
            else:
                endpoint_counts[endpoint] = 1

#  most accessed endpoint
most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
print(f"Most Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

failed_logins = {}  
threshold = 10  

for line in log_lines:
    if "401" in line or "Invalid credentials" in line:  # Check for failed logins
        parts = line.split()
        if parts:
            ip = parts[0]  # Extract the IP address
            if ip in failed_logins:
                failed_logins[ip] += 1
            else:
                failed_logins[ip] = 1

# Flag suspicious IPs
suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

print("Suspicious Activity Detected:")
print("IP Address           Failed Login Attempts")
for ip, count in suspicious_ips.items():
    print(f"{ip:<20}{count}")

import csv

# File name
output_file = "log_analysis_results.csv"

with open(output_file, mode="w", newline="") as file:
    writer = csv.writer(file)

    # Section 1: Requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in ip_counts.items():
        writer.writerow([ip, count])

    # Section 2: Most Accessed Endpoint
    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

    # Section 3: Suspicious Activity
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])

print(f"Results saved to {output_file}")
