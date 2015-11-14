class PStream::Error < RuntimeError
end

require "pstream/error/pcap_not_found"
require "pstream/error/pcap_not_readable"
require "pstream/error/tshark_not_found"
