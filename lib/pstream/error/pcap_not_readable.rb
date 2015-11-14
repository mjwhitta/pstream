class PStream::Error::PcapNotReadable < PStream::Error
    def initialize(pcap)
        super("File not readable: #{pcap}")
    end
end
