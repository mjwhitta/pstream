class PStream::Error::PcapNotFound < PStream::Error
    def initialize(pcap)
        super("File not found: #{pcap}")
    end
end
